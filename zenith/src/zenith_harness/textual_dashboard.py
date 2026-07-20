"""Terminal-only Textual dashboard for Zenith live snapshots."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Static

from .live import LiveSnapshot
from .live_dashboard import DashboardViewModel, build_dashboard_view_model


NowProvider = Callable[[], datetime | float | int]
SnapshotProvider = Callable[[], LiveSnapshot]


class ZenithDashboardApp(App[None]):
    """Read-only terminal dashboard for supervising Zenith project buckets."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #layout {
        height: 1fr;
    }

    #intervention {
        height: 5;
        border: heavy $accent;
    }

    #fleet {
        width: 52;
        height: 1fr;
    }

    #middle {
        width: 1fr;
        height: 1fr;
    }

    #right {
        width: 46;
        height: 1fr;
    }

    #detail {
        height: 3fr;
    }

    #tasks {
        height: 1fr;
    }

    #output {
        height: 2fr;
    }

    #attention {
        height: 1fr;
    }

    #aggregation {
        height: 1fr;
    }

    #consumption {
        height: 1fr;
    }

    #actions {
        height: 1fr;
    }

    Static {
        border: solid $panel;
        padding: 0 1;
        overflow: auto;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("j", "next_flow", "Next flow"),
        Binding("k", "previous_flow", "Previous flow"),
        Binding("n", "next_task", "Next task"),
        Binding("b", "previous_task", "Previous task"),
        Binding("p", "toggle_pin", "Pin"),
        Binding("f", "toggle_full_list", "Full list"),
        Binding("o", "toggle_output", "Output"),
        Binding("a", "toggle_attention", "Attention"),
    ]

    def __init__(
        self,
        *,
        snapshot_provider: SnapshotProvider,
        refresh_interval: float | None = 2.0,
        pinned_project_ids: set[str] | None = None,
        now_provider: NowProvider | None = None,
    ) -> None:
        super().__init__()
        self.snapshot_provider = snapshot_provider
        self.refresh_interval = refresh_interval
        self.pinned_project_ids = set(pinned_project_ids or set())
        self.now_provider = now_provider
        self.snapshot: LiveSnapshot | None = None
        self.model: DashboardViewModel | None = None
        self.selected_project_id: str | None = None
        self.selected_task_id: str | None = None
        self.show_full_list = False
        self.output_full = False
        self.attention_expanded = False
        self.last_error: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("", id="intervention", markup=False)
        with Horizontal(id="layout"):
            yield Static("", id="fleet", markup=False)
            with Vertical(id="middle"):
                yield Static("", id="detail", markup=False)
                yield Static("", id="tasks", markup=False)
            with Vertical(id="right"):
                yield Static("", id="output", markup=False)
                yield Static("", id="attention", markup=False)
                yield Static("", id="aggregation", markup=False)
                yield Static("", id="consumption", markup=False)
                yield Static("", id="actions", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_snapshot()
        if self.refresh_interval and self.refresh_interval > 0:
            self.set_interval(self.refresh_interval, self._refresh_snapshot)

    def action_refresh(self) -> None:
        self._refresh_snapshot()

    def action_next_flow(self) -> None:
        self._move_flow(1)

    def action_previous_flow(self) -> None:
        self._move_flow(-1)

    def action_next_task(self) -> None:
        self._move_task(1)

    def action_previous_task(self) -> None:
        self._move_task(-1)

    def action_toggle_pin(self) -> None:
        if not self.selected_project_id:
            return
        if self.selected_project_id in self.pinned_project_ids:
            self.pinned_project_ids.remove(self.selected_project_id)
        else:
            self.pinned_project_ids.add(self.selected_project_id)
        self._rebuild_model()

    def action_toggle_full_list(self) -> None:
        self.show_full_list = not self.show_full_list
        self._rebuild_model()

    def action_toggle_output(self) -> None:
        self.output_full = not self.output_full
        self._rebuild_model()

    def action_toggle_attention(self) -> None:
        self.attention_expanded = not self.attention_expanded
        self._rebuild_model()

    def _refresh_snapshot(self) -> None:
        try:
            self.snapshot = self.snapshot_provider()
            self.last_error = None
        except Exception as exc:  # pragma: no cover - defensive TUI rendering
            self.last_error = str(exc)
        self._rebuild_model()

    def _rebuild_model(self) -> None:
        if self.snapshot is None:
            self._render_error()
            return
        now = self.now_provider() if self.now_provider else None
        self.model = build_dashboard_view_model(
            self.snapshot,
            pinned_project_ids=self.pinned_project_ids,
            selected_project_id=self.selected_project_id,
            selected_task_id=self.selected_task_id,
            now=now,
            show_full_list=self.show_full_list,
            output_full=self.output_full,
            attention_expanded=self.attention_expanded,
        )
        self.selected_project_id = self.model.selected_project_id
        self.selected_task_id = self.model.selected_task_id
        self._render_model()

    def _move_flow(self, delta: int) -> None:
        if self.model is None or not self.model.visible_flows:
            return
        ids = [flow.id for flow in self.model.visible_flows]
        try:
            index = ids.index(self.selected_project_id or "")
        except ValueError:
            index = 0
        self.selected_project_id = ids[(index + delta) % len(ids)]
        self.selected_task_id = None
        self._rebuild_model()

    def _move_task(self, delta: int) -> None:
        if self.model is None or not self.model.detail.tasks:
            return
        ids = [task.id for task in self.model.detail.tasks]
        try:
            index = ids.index(self.selected_task_id or "")
        except ValueError:
            index = 0
        self.selected_task_id = ids[(index + delta) % len(ids)]
        self._rebuild_model()

    def _render_model(self) -> None:
        if self.model is None:
            self._render_error()
            return
        self._set_panel("intervention", self.model.render_intervention())
        self._set_panel("fleet", self.model.render_fleet())
        self._set_panel("detail", self.model.render_detail())
        self._set_panel("tasks", self.model.render_tasks())
        self._set_panel("output", self.model.render_output())
        self._set_panel("attention", self.model.render_attention())
        self._set_panel("aggregation", self.model.render_aggregation())
        self._set_panel("consumption", self.model.render_consumption())
        self._set_panel("actions", self.model.render_actions())

    def _render_error(self) -> None:
        text = self.last_error or "Dashboard snapshot is not available yet."
        for panel_id in (
            "intervention",
            "fleet",
            "detail",
            "tasks",
            "output",
            "attention",
            "aggregation",
            "consumption",
            "actions",
        ):
            self._set_panel(panel_id, text)

    def _set_panel(self, panel_id: str, value: str) -> None:
        widget = self.query_one(f"#{panel_id}", Static)
        widget.update(value)
