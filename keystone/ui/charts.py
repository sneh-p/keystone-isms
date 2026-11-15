"""Small chart helpers. Colours follow the status palette (good/warning/serious/critical);
every coloured cell also carries a text label, so colour never carries meaning alone."""

from __future__ import annotations

import html

import streamlit as st

STATUS = {"Low": "#0ca30c", "Medium": "#fab219", "High": "#ec835a", "Critical": "#d03b3b"}
INK = {"Low": "#ffffff", "Medium": "#0b0b0b", "High": "#0b0b0b", "Critical": "#ffffff"}


def heat_map(grid: list[list[int]], level_fn, likelihood_labels: dict, impact_labels: dict, title: str) -> None:
    """grid[impact-1][likelihood-1] = count. Impact on the y-axis (5 at top)."""
    rows = []
    for im in range(5, 0, -1):
        cells = [f'<th class="ks-ax" title="{html.escape(impact_labels[im])}">{im}</th>']
        for lk in range(1, 6):
            level = level_fn(lk, im)
            n = grid[im - 1][lk - 1]
            tip = html.escape(f"Likelihood {lk} ({likelihood_labels[lk]}) x Impact {im} ({impact_labels[im]}) = {lk * im}: {level}. {n} risk(s).")
            cells.append(
                f'<td title="{tip}" style="background:{STATUS[level]};color:{INK[level]}">'
                f'<b>{n or ""}</b><span>{level[0]}</span></td>'
            )
        rows.append("<tr>" + "".join(cells) + "</tr>")
    axis = '<tr><th></th>' + "".join(f'<th class="ks-ax" title="{html.escape(likelihood_labels[i])}">{i}</th>' for i in range(1, 6)) + "</tr>"
    st.markdown(
        f"""
<style>
.ks-hm {{border-collapse:separate;border-spacing:2px;margin:0 auto}}
.ks-hm td {{width:52px;height:44px;text-align:center;border-radius:4px;font-size:15px;position:relative}}
.ks-hm td span {{position:absolute;right:4px;bottom:2px;font-size:10px;opacity:.85}}
.ks-hm .ks-ax {{font-weight:400;font-size:12px;opacity:.7;padding:2px 6px}}
.ks-hm caption {{caption-side:top;font-weight:600;padding-bottom:4px}}
</style>
<table class="ks-hm" role="grid" aria-label="{html.escape(title)}">
<caption>{html.escape(title)}</caption>
{''.join(rows)}{axis}
</table>
<p style="text-align:center;font-size:12px;opacity:.7;margin-top:4px">Likelihood → · Impact ↑ · cells show number of risks and level (L/M/H/C)</p>
""",
        unsafe_allow_html=True,
    )
