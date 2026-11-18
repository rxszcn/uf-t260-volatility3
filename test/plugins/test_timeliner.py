# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the timeliner plugin's row assembly loop.

These tests exercise Timeliner._generator directly with fake
TimeLinerInterface plugins, so no memory image is required.  They cover:

* each (plugin, item) entry produces exactly one grid row, and every date
  column is taken from that entry's own timestamps (no cross-plugin or
  cross-entry date contamination, no duplicated rows)
* absent timestamps stay absent (BaseAbsentValue) in the grid and "0" in
  the bodyfile
* the bodyfile export contains exactly one line per entry, consistent with
  the grid
* a plugin (in particular the first one) producing no entries does not
  silently swallow other plugins' rows
"""

import datetime
import io

from volatility3 import framework
from volatility3.framework import contexts, interfaces, renderers
from volatility3.plugins import timeliner


def _dt(day: int) -> datetime.datetime:
    """Distinct, timezone-aware timestamps so cross-contamination is visible."""
    return datetime.datetime(2020, 1, day, 12, 0, 0, tzinfo=datetime.timezone.utc)


# Timestamps used by the fake plugins below
ALPHA_CREATED = _dt(1)
ALPHA_MODIFIED = _dt(2)
BETA_CREATED = _dt(3)
BETA_ACCESSED = _dt(4)
BETA_CHANGED = _dt(5)


class _FakePluginBase(timeliner.TimeLinerInterface):
    """Base for fake timeliner plugins, pinned to the current framework."""

    _required_framework_version = (2, 0, 0)


class EmptyPlugin(_FakePluginBase):
    """A timeliner plugin that produces no entries at all."""

    def generate_timeline(self):
        return iter([])


class PluginAlpha(_FakePluginBase):
    def generate_timeline(self):
        yield ("alpha-item", timeliner.TimeLinerType.CREATED, ALPHA_CREATED)
        yield ("alpha-item", timeliner.TimeLinerType.MODIFIED, ALPHA_MODIFIED)


class PluginBeta(_FakePluginBase):
    def generate_timeline(self):
        yield ("beta-item", timeliner.TimeLinerType.CREATED, BETA_CREATED)
        yield ("beta-item", timeliner.TimeLinerType.ACCESSED, BETA_ACCESSED)
        yield ("beta-item", timeliner.TimeLinerType.CHANGED, BETA_CHANGED)


class FakeFileHandler(interfaces.plugins.FileHandlerInterface):
    """Captures files the plugin writes into an in-memory buffer."""

    contents = {}

    def __init__(self, filename: str) -> None:
        super().__init__(filename)
        self._buffer = io.BytesIO()

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        return self._buffer.write(data)

    def close(self) -> None:
        if not self.closed:
            type(self).contents[self.preferred_filename] = self._buffer.getvalue()
        super().close()


def _make_timeliner(create_bodyfile: bool = False) -> timeliner.Timeliner:
    plugin = timeliner.Timeliner(contexts.Context(), "timeliner")
    plugin.config["create-bodyfile"] = create_bodyfile
    if create_bodyfile:
        FakeFileHandler.contents = {}
        plugin.set_open_method(FakeFileHandler)
    return plugin


def _rows_by_entry(rows):
    """Maps (plugin_name, item) to the row's value list, asserting uniqueness."""
    result = {}
    for depth, values in rows:
        assert depth == 0
        key = (values[0], values[1])
        assert key not in result, f"duplicate grid row for {key}"
        result[key] = values
    return result


class TestTimelinerRowAssembly:
    def test_each_entry_one_row_with_own_dates(self):
        """Each plugin entry yields exactly one row whose four date columns
        come from that entry's own timestamps; absent values stay absent."""
        plugin = _make_timeliner()
        rows = list(plugin._generator([PluginAlpha(), PluginBeta()]))

        by_entry = _rows_by_entry(rows)
        assert set(by_entry) == {
            ("PluginAlpha", "alpha-item"),
            ("PluginBeta", "beta-item"),
        }

        # Columns: Plugin, Description, Created, Modified, Accessed, Changed
        alpha = by_entry[("PluginAlpha", "alpha-item")]
        assert alpha[2] == ALPHA_CREATED
        assert alpha[3] == ALPHA_MODIFIED
        assert isinstance(alpha[4], interfaces.renderers.BaseAbsentValue)
        assert isinstance(alpha[5], interfaces.renderers.BaseAbsentValue)

        beta = by_entry[("PluginBeta", "beta-item")]
        assert beta[2] == BETA_CREATED
        assert isinstance(beta[3], interfaces.renderers.BaseAbsentValue)
        assert beta[4] == BETA_ACCESSED
        assert beta[5] == BETA_CHANGED

    def test_empty_first_plugin_does_not_drop_rows(self):
        """An empty first plugin must not silently swallow later rows."""
        plugin = _make_timeliner()
        rows = list(plugin._generator([EmptyPlugin(), PluginAlpha(), PluginBeta()]))

        by_entry = _rows_by_entry(rows)
        assert set(by_entry) == {
            ("PluginAlpha", "alpha-item"),
            ("PluginBeta", "beta-item"),
        }
        assert by_entry[("PluginAlpha", "alpha-item")][2] == ALPHA_CREATED
        assert by_entry[("PluginBeta", "beta-item")][4] == BETA_ACCESSED

    def test_bodyfile_matches_grid(self):
        """The bodyfile holds exactly one line per entry, with the same
        per-entry dates as the grid (absent values exported as 0)."""
        plugin = _make_timeliner(create_bodyfile=True)
        rows = list(plugin._generator([PluginAlpha(), PluginBeta()]))
        by_entry = _rows_by_entry(rows)

        body = FakeFileHandler.contents["volatility.body"].decode("utf-8")
        lines = [line for line in body.splitlines() if line]
        assert len(lines) == len(by_entry)

        def epoch(value):
            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                return "0"
            return str(int(value.timestamp()))

        expected = set()
        for (plugin_name, item), values in by_entry.items():
            # Body format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
            expected.add(
                "|{} - {}|0|0|0|0|0|{}|{}|{}|{}".format(
                    plugin_name,
                    item,
                    epoch(values[4]),  # atime = Accessed
                    epoch(values[3]),  # mtime = Modified
                    epoch(values[5]),  # ctime = Changed
                    epoch(values[2]),  # crtime = Created
                )
            )
        assert set(lines) == expected
