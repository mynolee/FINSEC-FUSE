"""Explicit ASGI construction; importing this module does not start an agent."""
from __future__ import annotations

from .product_provider import ProductSettings, configure_product_providers
from .product_messages import PreparedProductPrompt


def create_product_app(
    config: ProductSettings,
    *,
    adapter_factory=None,
    live_factory=None,
    prompt_loader=None,
    message_builder=None,
    prepared_prompt=None,
):
    """Return an app after installing explicit, already-created dependencies."""
    if prepared_prompt is not None and type(prepared_prompt) is not PreparedProductPrompt:
        raise TypeError("Prepared product prompt data is required")
    if not isinstance(config, ProductSettings):
        raise TypeError("An explicit ProductSettings object is required")
    if config.errors():
        raise RuntimeError("Internal service token is missing or invalid")
    configure_product_providers(
        config,
        adapter_factory=adapter_factory,
        live_factory=live_factory,
        prompt_loader=prompt_loader,
        message_builder=message_builder,
    )
    from .app import create_app
    return create_app(prepared_prompt=prepared_prompt)
