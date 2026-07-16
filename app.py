import streamlit as st
import pandas as pd
import io
import os
import re
import tempfile
import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import matplotlib.pyplot as plt
from datetime import datetime

st.set_page_config(page_title='CI Monitor', page_icon='⚙️', layout='wide')

ACCENT = '#3b82f6'

st.markdown(f'''
<style>
.block-container {{padding-top: 3rem;}}

.brand {{display:flex; align-items:center; gap:10px; margin-bottom:18px;}}
.brand-icon {{
    width:34px; height:34px; border-radius:9px; background:{ACCENT};
    display:flex; align-items:center; justify-content:center; font-weight:800; color:white; font-size:1rem;
}}
.brand-title {{font-size:1.15rem; font-weight:800; color:#f3f4f6;}}
.sidebar-footer {{font-size:.78rem; opacity:.6; margin-top:4px;}}

.dash-title {{font-size:1.9rem; font-weight:800; margin:0;}}
.dash-subtitle {{opacity:.65; font-size:.9rem; margin-top:4px;}}

.kpi-card {{
    border:1px solid rgba(120,120,120,.18); border-radius:16px; padding:18px 18px 14px 18px;
    background:rgba(127,127,127,.05); min-height:150px; position:relative; overflow:hidden;
}}
.kpi-icon {{
    width:36px; height:36px; border-radius:10px; display:flex; align-items:center; justify-content:center;
    font-size:1.05rem; margin-bottom:10px;
}}
.kpi-label {{font-size:.72rem; opacity:.65; text-transform:uppercase; letter-spacing:.03em; margin-bottom:2px;}}
.kpi-value {{font-size:1.9rem; font-weight:800; margin-top:2px; line-height:1.15;}}
.kpi-note {{font-size:.76rem; opacity:.6; margin-top:5px;}}
.note {{border-left:4px solid {ACCENT}; padding:10px 12px; background:rgba(59,130,246,.08); border-radius:6px;}}
</style>
''', unsafe_allow_html=True)

# -----------------------------------------------------------------------
# DATA LAYER
# Expected columns (from the issue tracker export):
#   Issue ID, Status, Failure Category, Short Message, Error Description,
#   Recommended Fix, Workflow Name, Branch, Failed Stage, Build URL,
#   Created Time, Run
#
# Run        -> Success / Fail  (the CI run outcome)
# Status     -> Open / Resolve  (whether the failure has been fixed)
# -----------------------------------------------------------------------

REQUIRED_COLS = [
    'Issue ID', 'Status', 'Failure Category', 'Short Message',
    'Error Description', 'Recommended Fix', 'Workflow Name', 'Branch',
    'Failed Stage', 'Build URL', 'Created Time', 'Run'
]

# Set this once and the dashboard loads automatically on every run — no manual pasting needed.
DEFAULT_SHEET_URL = 'https://docs.google.com/spreadsheets/d/1xtWH0PqfvNa0xH-ECc2czkDruKJbQqmhs7NRdCvPnYg/edit?usp=sharing'

# -----------------------------------------------------------------------
# NETWORK / PROXY HANDLING
# On a VM behind a corporate proxy, outbound requests can fail for a few
# different reasons: the proxy isn't picked up automatically, the proxy
# does TLS interception so the cert chain doesn't validate, or the proxy
# needs auth. This section centralizes all of that so it's configurable
# from the UI instead of needing a code change every time.
# -----------------------------------------------------------------------

def _get_network_settings():
    """Reads proxy/SSL settings from session_state, falling back to env vars
    (HTTP_PROXY / HTTPS_PROXY / REQUESTS_CA_BUNDLE) which is what most
    corporate VM images set at the OS level."""
    return {
        'http_proxy': st.session_state.get('net_http_proxy', '') or os.environ.get('HTTP_PROXY', '') or os.environ.get('http_proxy', ''),
        'https_proxy': st.session_state.get('net_https_proxy', '') or os.environ.get('HTTPS_PROXY', '') or os.environ.get('https_proxy', ''),
        'verify_ssl': st.session_state.get('net_verify_ssl', True),
        'ca_bundle_path': st.session_state.get('net_ca_bundle_path', '') or os.environ.get('REQUESTS_CA_BUNDLE', ''),
    }


def _build_session(net):
    """Builds a requests.Session configured with the given proxy/SSL settings
    plus sane retries, so a flaky corporate proxy doesn't fail on the first
    hiccup."""
    session = requests.Session()

    proxies = {}
    if net['http_proxy']:
        proxies['http'] = net['http_proxy']
    if net['https_proxy']:
        proxies['https'] = net['https_proxy']
    if proxies:
        session.proxies.update(proxies)

    # Verification precedence: explicit CA bundle > disable verify flag > default True
    if net['ca_bundle_path']:
        session.verify = net['ca_bundle_path']
    else:
        session.verify = net['verify_ssl']

    retry = Retry(
        total=3, connect=3, read=3, backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504], allowed_methods=['GET'],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def _diagnose_connection(net):
    """Runs a small ladder of checks and returns (ok: bool, message: str)
    describing exactly which layer is failing, so the fix is obvious instead
    of guessing from a generic 'connection error'."""
    session = _build_session(net)
    steps = []

    # Step 1: can we reach anything at all through the configured proxy?
    try:
        r = session.get('https://www.google.com', timeout=10)
        steps.append(f"✅ Outbound HTTPS through proxy works (status {r.status_code}).")
    except requests.exceptions.ProxyError as e:
        return False, (
            "❌ Proxy connection failed at the proxy itself.\n\n"
            f"Details: {e}\n\n"
            "This usually means: wrong proxy host/port, the proxy requires "
            "authentication (try `http://user:pass@proxyhost:port`), or the VM "
            "can't reach the proxy host on that port (check with your network team)."
        )
    except requests.exceptions.SSLError as e:
        return False, (
            "❌ TLS/SSL certificate verification failed.\n\n"
            f"Details: {e}\n\n"
            "Your corporate proxy is very likely doing TLS inspection (MITM), which "
            "swaps in its own certificate. Fix: download your corporate root CA "
            "certificate (.pem/.crt, ask your IT/security team) and upload it below "
            "in 'Corporate CA bundle', or as a quick unblock, temporarily disable "
            "SSL verification (not recommended for anything sensitive)."
        )
    except requests.exceptions.ConnectTimeout as e:
        return False, (
            "❌ Connection timed out reaching the proxy or the internet.\n\n"
            f"Details: {e}\n\n"
            "Check that the proxy host/port is correct and reachable from this VM "
            "(e.g. `curl -v -x <proxy> https://www.google.com` from a terminal), "
            "and that outbound firewall rules allow this VM to reach the proxy."
        )
    except requests.exceptions.ConnectionError as e:
        return False, (
            "❌ Could not establish a connection at all.\n\n"
            f"Details: {e}\n\n"
            "If no proxy is configured, the VM's network may require one — ask your "
            "network team for the proxy host/port and enter it below. If a proxy IS "
            "configured, double-check the host/port for typos."
        )
    except Exception as e:
        return False, f"❌ Unexpected error during connectivity check: {e}"

    # Step 2: can we reach Google Sheets specifically (some proxies allow
    # general web but block/whitelist specific domains)?
    try:
        r = session.get('https://docs.google.com', timeout=10)
        steps.append(f"✅ docs.google.com is reachable (status {r.status_code}).")
    except Exception as e:
        steps.append(f"⚠️ General internet works, but docs.google.com specifically failed: {e}. "
                      f"Your proxy may whitelist domains — ask IT to allow docs.google.com and googleusercontent.com.")
        return False, "\n".join(steps)

    return True, "\n".join(steps) + "\n\nConnectivity looks good — the sheet load should work now."


def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]

    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        st.error(f"Missing expected column(s): {', '.join(missing)}. "
                 f"Found columns: {', '.join(df.columns)}")
        st.stop()

    df['Status'] = df['Status'].astype(str).str.strip().str.title()
    df['Status'] = df['Status'].replace({'Resolve': 'Resolved'})
    df['Run'] = df['Run'].astype(str).str.strip().str.title()
    df['Failure Category'] = df['Failure Category'].astype(str).str.strip().str.rstrip(',')
    df['Workflow Name'] = df['Workflow Name'].astype(str).str.strip()
    df['Branch'] = df['Branch'].astype(str).str.strip()

    return df


def _extract_sheet_id(share_url: str) -> str:
    match = re.search(r'/spreadsheets/d/([a-zA-Z0-9-_]+)', share_url)
    if not match:
        raise ValueError('That doesn\'t look like a Google Sheets link (expected .../spreadsheets/d/<id>/...).')
    return match.group(1)


@st.cache_data(ttl=300, show_spinner='Fetching latest data from Google Sheets...')
def load_sheet_from_url(share_url: str, net: dict):
    sheet_id = _extract_sheet_id(share_url)
    csv_url = f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv'
    session = _build_session(net)

    try:
        resp = session.get(csv_url, timeout=20)
    except requests.exceptions.SSLError as e:
        raise RuntimeError(
            'SSL certificate verification failed — your corporate proxy is likely doing '
            'TLS inspection. Go to Data source → Proxy / SSL settings and either upload your '
            f'corporate CA bundle or disable SSL verification. Raw error: {e}'
        )
    except requests.exceptions.ProxyError as e:
        raise RuntimeError(
            'Could not connect through the configured proxy. Check the proxy host/port '
            f'in Data source → Proxy / SSL settings (include username:password if the proxy '
            f'needs auth). Raw error: {e}'
        )
    except requests.exceptions.ConnectTimeout as e:
        raise RuntimeError(
            f'Connection to the proxy/internet timed out. Raw error: {e}'
        )
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            'Could not establish a connection. If this VM sits behind a corporate proxy, '
            f'set the proxy host/port in Data source → Proxy / SSL settings. Raw error: {e}'
        )

    if resp.status_code != 200 or resp.text.strip().startswith('<'):
        raise RuntimeError(
            'Could not download the sheet as CSV. Make sure sharing is set to '
            '"Anyone with the link" → Viewer (File → Share → General access). '
            f'(HTTP status: {resp.status_code})'
        )
    df = pd.read_csv(io.StringIO(resp.text))
    return _clean_columns(df)


@st.cache_data
def load_excel(file_bytes):
    df = pd.read_excel(io.BytesIO(file_bytes))
    return _clean_columns(df)


def sparkline_svg(color, seed_text, width=140, height=28):
    # Deterministic decorative trend line (illustrative only — the sheet has no
    # per-day history to plot a real trend from). Seeded so it's stable per card.
    seed = int(hashlib.md5(seed_text.encode()).hexdigest(), 16)
    n = 10
    pts = []
    val = 0.5
    for i in range(n):
        seed = (seed * 1103515245 + 12345) & 0x7fffffff
        val += ((seed % 1000) / 1000 - 0.5) * 0.6
        val = max(0.05, min(0.95, val))
        x = i / (n - 1) * width
        y = height - (val * height)
        pts.append(f'{x:.1f},{y:.1f}')
    points = ' '.join(pts)
    return (f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'style="display:block;margin-top:10px;">'
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/></svg>')


def kpi(label, value, note, icon, icon_bg, icon_color, value_color='#f3f4f6'):
    spark = sparkline_svg(icon_color, label)
    st.markdown(f"""
    <div class='kpi-card'>
        <div class='kpi-icon' style='background:{icon_bg}; color:{icon_color};'>{icon}</div>
        <div class='kpi-label'>{label}</div>
        <div class='kpi-value' style='color:{value_color};'>{value}</div>
        <div class='kpi-note'>{note}</div>
        {spark}
    </div>
    """, unsafe_allow_html=True)


def donut(title_center, labels, values, colors, px_width=240):
    total = sum(values)
    fig, ax = plt.subplots(figsize=(3.0, 3.0), dpi=220)
    fig.patch.set_alpha(0)
    ax.set_facecolor('none')

    ax.pie(
        values, colors=colors, startangle=90, counterclock=False,
        wedgeprops={'width': 0.4, 'edgecolor': '#0b1220', 'linewidth': 1.5}
    )
    ax.text(0, 0.10, f'{total:,}', ha='center', va='center', fontsize=22, fontweight='bold', color='white')
    ax.text(0, -0.16, title_center, ha='center', va='center', fontsize=10, color='#9ca3af')
    ax.axis('equal')
    plt.tight_layout(pad=0.2)

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=220, transparent=True, bbox_inches='tight', pad_inches=0.03)
    plt.close(fig)
    buf.seek(0)

    img_col, legend_col = st.columns([1, 1])
    with img_col:
        st.image(buf, width=px_width)
    with legend_col:
        st.markdown('<div style="margin-top:22px;">', unsafe_allow_html=True)
        for lab, val, col in zip(labels, values, colors):
            pct = (val / total * 100) if total else 0
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:.85rem;'>"
                f"<span style='width:9px;height:9px;border-radius:50%;background:{col};display:inline-block;flex-shrink:0;'></span>"
                f"<span style='color:#e5e7eb;min-width:70px;'>{lab}</span>"
                f"<span style='color:#f3f4f6;font-weight:700;'>{val:,}</span>"
                f"<span style='color:#9ca3af;'>({pct:.0f}%)</span>"
                f"</div>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# -----------------------------------------------------------------------
# SIDEBAR — brand + nav + data source status
# Nav is plain HTML links (not st.button) so we have full control over
# styling — Streamlit's built-in button CSS is unreliable to override.
# -----------------------------------------------------------------------
NAV_ITEMS = [
    ('Overview', '▦'),
    ('Full logs', '▤'),
    ('Data source', '⚙'),
]

try:
    current_page = st.query_params.get('page', 'Overview')
except Exception:
    current_page = st.experimental_get_query_params().get('page', ['Overview'])[0]

if current_page not in [n for n, _ in NAV_ITEMS]:
    current_page = 'Overview'

nav_html = f"""
<div class='brand'>
    <div class='brand-icon'>C</div>
    <div class='brand-title'>CI Monitor</div>
</div>
<div style='margin-bottom:14px;'>
"""
for name, icon in NAV_ITEMS:
    is_active = (name == current_page)
    bg = 'rgba(59,130,246,.16)' if is_active else 'transparent'
    color = ACCENT if is_active else '#cbd5e1'
    weight = 700 if is_active else 500
    nav_html += (
        f"<a href='?page={name.replace(' ', '+')}' target='_self' "
        f"style='display:block; text-decoration:none; background:{bg}; color:{color}; "
        f"font-weight:{weight}; border-radius:10px; padding:9px 12px; margin-bottom:4px; "
        f"font-size:.95rem;'>{icon}&nbsp;&nbsp;&nbsp;{name}</a>"
    )
nav_html += "</div>"
st.sidebar.markdown(nav_html, unsafe_allow_html=True)

page = current_page

st.sidebar.markdown('<hr style="margin:1.2rem 0;opacity:.15;">', unsafe_allow_html=True)

# -----------------------------------------------------------------------
# DATA LOADING — runs regardless of which page is active, so Overview /
# Full logs always have data even if the user never visits Data source.
# -----------------------------------------------------------------------
if 'sheet_url' not in st.session_state:
    st.session_state['sheet_url'] = DEFAULT_SHEET_URL
if 'source_mode' not in st.session_state:
    st.session_state['source_mode'] = 'Google Sheet link'

df = None
load_error = None
net_settings = _get_network_settings()

if st.session_state['source_mode'] == 'Google Sheet link':
    try:
        df = load_sheet_from_url(st.session_state['sheet_url'], net_settings)
        st.session_state['last_updated'] = datetime.now()
    except Exception as e:
        load_error = str(e)
else:
    uploaded_bytes = st.session_state.get('uploaded_bytes')
    if uploaded_bytes:
        df = load_excel(uploaded_bytes)
        st.session_state['last_updated'] = datetime.now()

last_updated = st.session_state.get('last_updated')
st.sidebar.markdown(f"""
<div class='sidebar-footer'>
    📅 Last updated<br>{last_updated.strftime('%b %d, %Y %I:%M %p') if last_updated else '—'}
</div>
""", unsafe_allow_html=True)

if df is None:
    st.title('CI Monitor')
    if load_error:
        st.error('Could not load data.')
        st.code(load_error)
    else:
        st.info('Go to the Data source page to connect a Google Sheet or upload an Excel file.')
    st.stop()

# -----------------------------------------------------------------------
# Shared lookups
# -----------------------------------------------------------------------
all_workflows = sorted(df['Workflow Name'].dropna().unique())
all_branches = sorted(df['Branch'].dropna().unique())

# -----------------------------------------------------------------------
# PAGE: DATA SOURCE
# -----------------------------------------------------------------------
if page == 'Data source':
    st.markdown("<div class='dash-title'>Data source</div>", unsafe_allow_html=True)
    st.markdown("<div class='dash-subtitle'>Connect and manage where CI Monitor reads its data from.</div>", unsafe_allow_html=True)
    st.write("")

    mode = st.radio('Load from', ['Google Sheet link', 'Manual upload'],
                     index=0 if st.session_state['source_mode'] == 'Google Sheet link' else 1)
    st.session_state['source_mode'] = mode

    if mode == 'Google Sheet link':
        url = st.text_input('Google Sheet share link (anyone with the link can view)',
                             value=st.session_state['sheet_url'])
        c1, c2 = st.columns([1, 4])
        with c1:
            if st.button('🔄 Refresh now'):
                st.session_state['sheet_url'] = url
                load_sheet_from_url.clear()
                st.rerun()
        if url != st.session_state['sheet_url']:
            st.session_state['sheet_url'] = url
            st.rerun()
        st.caption('Auto-refreshes every 5 minutes. Sharing must be set to "Anyone with the link → Viewer".')
    else:
        uploaded = st.file_uploader('Upload issue tracker Excel (.xlsx)', type=['xlsx', 'xls'])
        if uploaded is not None:
            st.session_state['uploaded_bytes'] = uploaded.getvalue()
            st.rerun()

    st.write("")
    if load_error:
        st.error('Could not load data.')
        st.code(load_error)
    else:
        st.markdown(f"<div class='note'>✅ Connected — {len(df):,} rows loaded, "
                    f"{len(all_workflows)} workflow(s), {len(all_branches)} branch(es).</div>",
                    unsafe_allow_html=True)

    st.caption('Expected columns: ' + ', '.join(REQUIRED_COLS))

    st.write("")
    with st.expander('🌐 Proxy / SSL settings (corporate network)', expanded=bool(load_error)):
        st.caption(
            'If this app runs on a VM behind a corporate proxy, outbound requests to '
            'Google Sheets can fail. Configure the proxy and/or corporate CA cert here, '
            'or run the test below to pinpoint what\'s failing.'
        )

        pc1, pc2 = st.columns(2)
        with pc1:
            http_proxy = st.text_input(
                'HTTP proxy', value=st.session_state.get('net_http_proxy', ''),
                placeholder='http://user:pass@proxyhost:8080',
                help='Leave blank to use the VM\'s HTTP_PROXY env var, if set.'
            )
        with pc2:
            https_proxy = st.text_input(
                'HTTPS proxy', value=st.session_state.get('net_https_proxy', ''),
                placeholder='http://user:pass@proxyhost:8080',
                help='Leave blank to use the VM\'s HTTPS_PROXY env var, if set. '
                     'Usually the same value as the HTTP proxy above.'
            )
        st.session_state['net_http_proxy'] = http_proxy
        st.session_state['net_https_proxy'] = https_proxy

        ca_file = st.file_uploader(
            'Corporate CA bundle (.pem / .crt) — needed if the proxy does TLS inspection',
            type=['pem', 'crt', 'cer']
        )
        if ca_file is not None:
            ca_path = os.path.join(tempfile.gettempdir(), 'corporate_ca_bundle.pem')
            with open(ca_path, 'wb') as f:
                f.write(ca_file.getvalue())
            st.session_state['net_ca_bundle_path'] = ca_path
            st.success(f'CA bundle saved and will be used for verification: {ca_path}')

        if st.session_state.get('net_ca_bundle_path'):
            cc1, cc2 = st.columns([3, 1])
            with cc1:
                st.caption(f"Currently using CA bundle: {st.session_state['net_ca_bundle_path']}")
            with cc2:
                if st.button('Clear CA bundle'):
                    st.session_state['net_ca_bundle_path'] = ''
                    st.rerun()

        verify_ssl = st.checkbox(
            '⚠️ Disable SSL verification (only as a last resort / quick unblock — '
            'not recommended, especially outside a trusted network)',
            value=not st.session_state.get('net_verify_ssl', True)
        )
        st.session_state['net_verify_ssl'] = not verify_ssl

        st.write("")
        if st.button('🔧 Test connection'):
            with st.spinner('Running connectivity checks...'):
                ok, msg = _diagnose_connection(_get_network_settings())
            if ok:
                st.success(msg)
            else:
                st.error(msg)

        if st.button('Apply & refresh data'):
            load_sheet_from_url.clear()
            st.rerun()

# -----------------------------------------------------------------------
# PAGE: OVERVIEW
# -----------------------------------------------------------------------
elif page == 'Overview':
    fdf = df

    total_runs = len(fdf)
    success_runs = (fdf['Run'] == 'Success').sum()
    failed_runs = (fdf['Run'] == 'Fail').sum()
    success_rate = (success_runs / total_runs * 100) if total_runs else 0

    issues = fdf
    open_issues = issues[issues['Status'] == 'Open']
    resolved_issues = issues[issues['Status'] == 'Resolved']
    resolved_rate = (len(resolved_issues) / len(issues) * 100) if len(issues) else 0

    header_left, header_right = st.columns([3, 1])
    with header_left:
        st.markdown(f"""
        <div class='dash-title'>CI Pipeline Health</div>
        <div class='dash-subtitle'>Overview of your CI pipeline performance and issue resolution &middot; {total_runs:,} runs loaded</div>
        """, unsafe_allow_html=True)
    with header_right:
        st.write("")
        st.download_button('⬇️ Export Report', fdf.to_csv(index=False).encode(), 'ci_pipeline_report.csv', 'text/csv', width='stretch')

    c = st.columns(4)
    with c[0]:
        kpi('Total runs', f'{total_runs:,}', f'{len(all_workflows)} workflow(s)',
            '▶', 'rgba(96,165,250,.15)', '#60a5fa')
    with c[1]:
        kpi('Success rate', f'{success_rate:.1f}%', f'{success_runs:,} successful runs',
            '✓', 'rgba(52,211,153,.15)', '#34d399', value_color='#34d399')
    with c[2]:
        kpi('Issues detected', f'{len(open_issues):,}', f'{len(issues):,} total tracked',
            '⚠', 'rgba(251,191,36,.15)', '#fbbf24', value_color='#fbbf24')
    with c[3]:
        kpi('Resolved', f'{len(resolved_issues):,}', f'{resolved_rate:.0f}% resolution rate',
            '✓', 'rgba(167,139,250,.15)', '#a78bfa', value_color='#a78bfa')

    left, mid, right, spacer = st.columns([1.15, 1.15, 1.15, 0.55])
    with left:
        with st.container(border=True):
            st.subheader('Successful vs failed runs')
            if total_runs:
                donut('runs', ['Success', 'Fail'], [success_runs, failed_runs], ['#34d399', '#f87171'])
            else:
                st.info('No runs in the current filter.')
    with right:
        with st.container(border=True):
            st.subheader('Open vs resolved issues')
            if len(issues):
                donut('issues', ['Open', 'Resolved'], [len(open_issues), len(resolved_issues)], ['#fbbf24', '#60a5fa'])
            else:
                st.info('No issues in the current filter.')

    st.subheader('Recent runs')
    recent = fdf.tail(3).iloc[::-1][['Issue ID', 'Status', 'Branch', 'Short Message']]
    st.dataframe(recent, hide_index=True, width='stretch')

# -----------------------------------------------------------------------
# PAGE: FULL LOGS
# -----------------------------------------------------------------------
else:
    st.markdown("<div class='dash-title'>Full logs</div>", unsafe_allow_html=True)
    st.write("")

    filter_cols = REQUIRED_COLS  # every column gets its own dropdown
    selected = {}

    with st.expander('🔍 Filters', expanded=True):
        for i in range(0, len(filter_cols), 4):
            row_cols = filter_cols[i:i + 4]
            cols = st.columns(4)
            for c, colname in zip(cols, row_cols):
                with c:
                    options = sorted(df[colname].dropna().astype(str).unique())
                    selected[colname] = st.multiselect(colname, options, default=options, key=f'filt_{colname}')

    mask = pd.Series(True, index=df.index)
    for colname, chosen in selected.items():
        mask &= df[colname].astype(str).isin(chosen)
    log = df[mask]

    st.caption(f'{len(log):,} rows')
    st.dataframe(log, hide_index=True, width='stretch')
    st.download_button('⬇️ Download CSV', log.to_csv(index=False).encode(), 'ci_full_log.csv', 'text/csv')

st.divider()
st.caption('Data refreshes automatically from the configured source. Change it anytime from the Data source page.')
