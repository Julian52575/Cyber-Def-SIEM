"""Each command's README.md, rendered for the dashboard's help view."""

from collections.abc import Sequence
from importlib.resources import files

from markdown_it import MarkdownIt
from markdown_it.common.utils import escapeHtml
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token
from markdown_it.utils import EnvType, OptionsDict
from markupsafe import Markup

# Raw HTML in the Markdown is escaped, never passed through.
_md = MarkdownIt("commonmark", {"html": False}).enable("table")


def _code_inline(
    renderer: RendererHTML,
    tokens: Sequence[Token],
    idx: int,
    options: OptionsDict,
    env: EnvType,
) -> str:
    # Lets names like application_layer_protocol_negotiation wrap on a phone,
    # at the underscores only, so short names in narrow columns stay whole.
    code = escapeHtml(tokens[idx].content).replace("_", "_<wbr>")
    return f"<code>{code}</code>"


_md.add_render_rule("code_inline", _code_inline)


def _is_relative(href: str) -> bool:
    return not href.startswith(("http://", "https://", "#"))


def _unlink_relative(tokens: list[Token]) -> None:
    """Relative links point into the repo, which the dashboard does not serve: keep their text."""
    for token in tokens:
        if token.children is None:
            continue
        kept: list[Token] = []
        dropping = False
        for child in token.children:
            if child.type == "link_open" and _is_relative(str(child.attrGet("href"))):
                dropping = True
                continue
            if child.type == "link_close" and dropping:
                dropping = False
                continue
            kept.append(child)
        token.children = kept


def render(markdown: str) -> Markup:
    tokens = _md.parse(markdown)
    _unlink_relative(tokens)
    return Markup(_md.renderer.render(tokens, _md.options, {}))


def command_help(command: str) -> Markup | None:
    """The rendered README of `command`, or None when it has none."""
    readme = files("my_siem") / command / "README.md"
    if not readme.is_file():
        return None
    return render(readme.read_text(encoding="utf-8"))
