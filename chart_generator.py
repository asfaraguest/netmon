#!/usr/bin/env python3
"""
NetMon - Traffic Chart Generator
Generates high-resolution, dark-themed traffic charts (PNG) for Telegram Bot and reporting.
Supports all NetMon time-series ranges (1h, 6h, 24h, 7d, 30d).
"""

import io
import re
from datetime import datetime

HAS_MATPLOTLIB = False
try:
    import matplotlib
    matplotlib.use('Agg')  # Headless mode for Linux server background processes
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.ticker import FuncFormatter
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def is_chart_available():
    """Check if matplotlib is available in the current environment."""
    return HAS_MATPLOTLIB


def render_traffic_chart_image(data):
    """
    Render a modern dark-themed PNG chart using data from Database.get_chart_traffic_data().
    
    Args:
        data (dict): Result dictionary from db.get_chart_traffic_data(...)
                     containing target_name, time_label, points, peak_rx, avg_rx, etc.
    
    Returns:
        bytes: Raw PNG image bytes, or None if matplotlib is unavailable.
    """
    if not HAS_MATPLOTLIB:
        return None

    target_name = data.get('target_name', 'Backbone Traffic')
    time_label = data.get('time_label', '24 Jam Terakhir')
    code = data.get('time_range', '24h')
    points = data.get('points', [])
    peak_rx = data.get('peak_rx', 0.0)
    peak_tx = data.get('peak_tx', 0.0)
    avg_rx = data.get('avg_rx', 0.0)
    avg_tx = data.get('avg_tx', 0.0)
    cur_rx = data.get('cur_rx', 0.0)
    cur_tx = data.get('cur_tx', 0.0)
    uplink_mbps = float(data.get('uplink_mbps') or 1000.0)

    # Bandwidth utilization percentages
    cur_rx_pct = (cur_rx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
    cur_tx_pct = (cur_tx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
    peak_rx_pct = (peak_rx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
    peak_tx_pct = (peak_tx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
    max_peak_pct = max(peak_rx_pct, peak_tx_pct)

    # Theme colors (matching NetMon Dark UI)
    bg_color = "#0f172a"      # Slate 900 (Canvas)
    axes_color = "#1e293b"    # Slate 800 (Plot area)
    border_color = "#334155"  # Slate 700 (Spines / Grid)
    text_color = "#f8fafc"    # Slate 50 (Headings)
    muted_color = "#94a3b8"   # Slate 400 (Labels / Subtitles)
    rx_color = "#00d4ff"      # Neon Cyan (WAN IN / Download)
    tx_color = "#10b981"      # Emerald Green (WAN OUT / Upload)

    fig, ax = plt.subplots(figsize=(10.5, 5.0), dpi=130, facecolor=bg_color)
    ax.set_facecolor(axes_color)

    # Parse timestamps into datetime objects
    dts, rx_vals, tx_vals = [], [], []
    for p in points:
        b_str = p.get('bucket', '')
        dt_obj = None
        for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
            try:
                dt_obj = datetime.strptime(b_str, fmt)
                break
            except ValueError:
                pass
        if dt_obj:
            dts.append(dt_obj)
            rx_vals.append(p.get('rx_mbps', 0.0))
            tx_vals.append(p.get('tx_mbps', 0.0))

    if len(dts) >= 2:
        # Plot Download (WAN IN)
        ax.plot(dts, rx_vals, color=rx_color, linewidth=2.0, label='WAN IN (Download)', zorder=3)
        ax.fill_between(dts, rx_vals, color=rx_color, alpha=0.18, zorder=2)

        # Plot Upload (WAN OUT)
        ax.plot(dts, tx_vals, color=tx_color, linewidth=2.0, label='WAN OUT (Upload)', zorder=3)
        ax.fill_between(dts, tx_vals, color=tx_color, alpha=0.18, zorder=2)

        # Configure X-axis date locators and formatters
        if code == '1h':
            ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=range(0, 60, 10)))
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        elif code == '6h':
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        elif code == '24h':
            ax.xaxis.set_major_locator(mdates.HourLocator(byhour=range(0, 24, 3)))
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        elif code == '7d':
            ax.xaxis.set_major_locator(mdates.DayLocator())
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%a %d'))
        elif code == '30d':
            ax.xaxis.set_major_locator(mdates.DayLocator(interval=5))
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%d %b'))

        # Set Y-axis limits and formatting
        max_val = max(peak_rx, peak_tx, 0.5)
        ax.set_ylim(bottom=0, top=max_val * 1.18)

        def y_fmt(val, _):
            if val >= 1000:
                return f"{val/1000:.1f} Gbps"
            elif val >= 100:
                return f"{int(val)} Mbps"
            elif val >= 1:
                return f"{val:.1f} Mbps"
            else:
                return f"{val:.2f} Mbps"

        ax.yaxis.set_major_formatter(FuncFormatter(y_fmt))

        # Legend with statistics overview (throughput rate & bandwidth usage)
        legend_labels = [
            f"WAN IN (Download)  • Cur: {cur_rx:.2f} Mbps ({cur_rx_pct:.1f}%) | Peak: {peak_rx:.2f} Mbps ({peak_rx_pct:.1f}%) | Avg: {avg_rx:.2f} Mbps",
            f"WAN OUT (Upload)   • Cur: {cur_tx:.2f} Mbps ({cur_tx_pct:.1f}%) | Peak: {peak_tx:.2f} Mbps ({peak_tx_pct:.1f}%) | Avg: {avg_tx:.2f} Mbps"
        ]
        leg = ax.legend(labels=legend_labels, loc='upper left', frameon=True,
                        facecolor=bg_color, edgecolor=border_color,
                        labelcolor=text_color, fontsize=8.2)
        leg.get_frame().set_alpha(0.88)

    else:
        # Placeholder when not enough data
        ax.text(0.5, 0.55, "Belum Ada Data Historis Traffic Cukup",
                color=text_color, fontsize=12, fontweight='bold', ha='center', va='center', transform=ax.transAxes)
        ax.text(0.5, 0.42, "Pastikan polling SNMP router aktif untuk rentang waktu ini.",
                color=muted_color, fontsize=9.5, ha='center', va='center', transform=ax.transAxes)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)

    # Grid styling
    ax.grid(True, linestyle='--', linewidth=0.6, color=border_color, alpha=0.7, zorder=1)

    # Axis spines styling
    for spine in ('top', 'right'):
        ax.spines[spine].set_visible(False)
    for spine in ('bottom', 'left'):
        ax.spines[spine].set_color(border_color)
        ax.spines[spine].set_linewidth(0.8)

    # Tick parameters
    ax.tick_params(colors=muted_color, labelsize=8.5, which='both')
    plt.xticks(rotation=0)

    # Y-axis label
    ax.set_ylabel("Throughput (Mbps)", color=muted_color, fontsize=9, labelpad=8)

    # Titles and watermarks
    uplink_str = f"{int(uplink_mbps)} Mbps" if uplink_mbps < 1000 else f"{uplink_mbps/1000:.1f} Gbps"
    fig.text(0.08, 0.95, target_name, color=text_color, fontsize=13, fontweight='bold', ha='left')
    fig.text(0.08, 0.90, f"Traffic Throughput & Bandwidth Usage • {time_label} ({len(points)} titik sampel)", color=muted_color, fontsize=9, ha='left')
    fig.text(0.92, 0.95, f"Kapasitas Uplink: {uplink_str} (Peak: {max_peak_pct:.1f}%)", color="#38bdf8", fontsize=9, fontweight='semibold', ha='right')
    fig.text(0.92, 0.90, "NetMon Network Monitor", color="#64748b", fontsize=8.5, ha='right')

    # Save to in-memory bytes
    buf = io.BytesIO()
    plt.tight_layout(rect=[0.05, 0.04, 0.96, 0.88])
    plt.savefig(buf, format='png', dpi=130, facecolor=bg_color, edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()
