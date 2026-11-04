"""Synthetic configuration boundaries only; no HTTP app/provider execution."""
import pytest

from agent import product_limits
from agent.product_limits import ProductLimits


def limits(**overrides):
    fields = {"http_header_max_bytes": 16384, "internal_response_max_bytes": 262144,
              "json_max_depth": 32, "max_parallel": 1, "model_timeout_seconds": 1.0}
    fields.update(overrides)
    return ProductLimits(**fields)


@pytest.mark.parametrize("value", [True, False, 0, -1, float("nan"), float("inf"),
                                  -float("inf"), 10 ** 1000])
def test_invalid_timeout_has_fixed_validation_error_without_cause(value):
    with pytest.raises(ValueError) as failure:
        limits(model_timeout_seconds=value)
    assert str(failure.value) == "Model timeout must be finite and positive"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize("field", ["http_header_max_bytes", "internal_response_max_bytes",
                                    "json_max_depth", "max_parallel", "max_request_bytes"])
def test_boolean_never_enters_integer_resource_limits(field):
    with pytest.raises(ValueError):
        limits(**{field: True})


@pytest.mark.parametrize("parallel", [1, 2, 3, 4])
def test_reviewed_parallel_and_pending_calculation_values_are_preserved(parallel):
    value = limits(max_parallel=parallel, model_timeout_seconds=0.01)
    assert value.max_parallel == parallel
    assert 2 * value.max_parallel == 2 * parallel
    assert value.model_timeout_seconds == 0.01


def test_subclass_cannot_skip_validation_and_enter_configured_limits(monkeypatch):
    monkeypatch.setattr(product_limits, "_limits", None)

    class SkippedValidation(ProductLimits):
        def __post_init__(self):
            pass

    invalid = SkippedValidation(http_header_max_bytes=True, internal_response_max_bytes=0,
                                json_max_depth=0, max_parallel=1000, model_timeout_seconds=float("inf"))
    with pytest.raises(TypeError, match="^Explicit ProductLimits are required$"):
        product_limits.configure_limits(invalid)
    assert product_limits._limits is None


def test_binding_revalidates_modified_builtin_instance_before_state_change(monkeypatch):
    monkeypatch.setattr(product_limits, "_limits", None)
    value = limits()
    object.__setattr__(value, "max_parallel", True)
    with pytest.raises(ValueError):
        product_limits.configure_limits(value)
    assert product_limits._limits is None


def test_finite_supplied_timeout_is_not_replaced_or_normalized(monkeypatch):
    monkeypatch.setattr(product_limits, "_limits", None)
    value = limits(model_timeout_seconds=10 ** 100)
    product_limits.configure_limits(value)
    assert product_limits.require_limits() is value
    assert type(value.model_timeout_seconds) is int
    assert value.model_timeout_seconds == 10 ** 100


def test_numeric_subclass_callbacks_are_not_used_for_timeout_validation():
    class CustomNumber(int):
        def __float__(self):
            raise AssertionError("Numeric conversion callback must not run")

        def __gt__(self, other):
            raise AssertionError("Numeric comparison callback must not run")

    with pytest.raises(ValueError, match="^Model timeout must be finite and positive$"):
        limits(model_timeout_seconds=CustomNumber(1))


def test_bound_limits_have_no_mutable_instance_dictionary(monkeypatch):
    monkeypatch.setattr(product_limits, "_limits", None)
    value = limits(max_parallel=4)
    product_limits.configure_limits(value)
    with pytest.raises(TypeError):
        vars(value)
    assert not hasattr(value, "__dict__")
    assert product_limits.require_limits().max_parallel == 4
