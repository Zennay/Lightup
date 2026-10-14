"""Offline opt-in #1095 exact primitive snapshot and real synthetic executor proof.

The default runtime remains unfixed. These green reference tests are NOT
authorization tests and do not remove the 14 intentional RED production canaries.
"""
from __future__ import annotations

import dataclasses
import tempfile
import unittest
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.primitive_admission_optin_1095 import (
    MAX_SYNTHETIC_BATCH_ITEMS,
    MAX_SYNTHETIC_PARAMETERS,
    PrimitiveBatchSnapshot,
    PrimitiveValueSnapshot,
    snapshot_exact_primitive_batch,
    snapshot_exact_primitive_values,
)
from lightup.state import StateStore


class StrSubclass(str):
    def __eq__(self, other):
        raise AssertionError("subclass __eq__ must never run")

    __hash__ = str.__hash__


class IntSubclass(int):
    def __int__(self):
        raise AssertionError("subclass __int__ must never run")


class FloatSubclass(float):
    def __float__(self):
        raise AssertionError("subclass __float__ must never run")


class NumberEnum(IntEnum):
    ONE = 1


def definition(name: str, kind: ParamKind, *, required: bool = True):
    return ToolDefinition(
        "synthetic-" + name, "external-attack-surface",
        InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
        "offline shape gate only",
        (ToolParameter("value", kind, required=required),),
    )


class ExactPrimitiveSnapshotTests(unittest.TestCase):
    def test_builtin_primitive_positive_controls(self):
        for kind, values in (
            (ParamKind.STRING, ("", "synthetic.invalid", "é")),
            (ParamKind.INTEGER, (0, -2, 42)),
            (ParamKind.NUMBER, (0, 1, -1, 1.5, -0.0)),
            (ParamKind.BOOLEAN, (True, False)),
        ):
            for value in values:
                with self.subTest(kind=kind.value, value=repr(value)):
                    snapshot = snapshot_exact_primitive_values(
                        definition("value", kind), {"value": value}
                    )
                    self.assertEqual(snapshot.as_arguments(), {"value": value})
                    self.assertIs(type(snapshot.as_arguments()), dict)
                    self.assertFalse(snapshot.authorization_verified)
                    self.assertFalse(snapshot.permit_issued)
                    self.assertFalse(snapshot.execution_enabled)

    def test_polymorphic_and_enum_values_are_denied_without_callbacks(self):
        for kind, value in (
            (ParamKind.STRING, StrSubclass("synthetic")),
            (ParamKind.INTEGER, IntSubclass(3)),
            (ParamKind.INTEGER, NumberEnum.ONE),
            (ParamKind.NUMBER, IntSubclass(3)),
            (ParamKind.NUMBER, NumberEnum.ONE),
            (ParamKind.NUMBER, FloatSubclass(2.25)),
        ):
            with self.subTest(kind=kind.value, exact_type=type(value).__name__):
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(definition("value", kind), {"value": value})

    def test_canonical_wrong_values_fail_closed(self):
        for kind, value in (
            (ParamKind.STRING, 10), (ParamKind.INTEGER, True),
            (ParamKind.NUMBER, False), (ParamKind.BOOLEAN, 1),
            (ParamKind.INTEGER, "3"), (ParamKind.NUMBER, None),
        ):
            with self.subTest(kind=kind.value, value=repr(value)):
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(definition("value", kind), {"value": value})

    def test_unknown_argument_and_missing_required_refused(self):
        for args in ({}, {"value": 1, "extra": "wrong"}):
            with self.subTest(args=repr(args)):
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(definition("int", ParamKind.INTEGER), args)

    def test_required_optional_metadata_preserves_optional_argument(self):
        tool = definition("optional", ParamKind.STRING, required=False)
        self.assertEqual(snapshot_exact_primitive_values(tool, {}).items, ())
        self.assertEqual(snapshot_exact_primitive_values(
            tool, {"value": "ok"}
        ).items, (("value", "ok"),))

    def test_noncanonical_dict_subclasses_and_keys_refused(self):
        tool = definition("text", ParamKind.STRING)
        for args in (
            {"value": "ok", 3: "extra"},
            {StrSubclass("value"): "ok"},
            type("DictSubclass", (dict,), {})({"value": "ok"}),
            [("value", "ok")],
        ):
            with self.assertRaises(OrchestrationError):
                snapshot_exact_primitive_values(tool, args)

    def test_snapshot_never_aliases_mutable_argument_container(self):
        original = {"value": "safe"}
        snap = snapshot_exact_primitive_values(definition("text", ParamKind.STRING), original)
        original["value"] = StrSubclass("unsafe")
        original["extra"] = "modified"
        self.assertEqual(snap.as_arguments(), {"value": "safe"})
        a = snap.as_arguments()
        a["value"] = "other"
        self.assertEqual(snap.as_arguments(), {"value": "safe"})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snap.items = ()

    def test_batch_all_rows_snapshotted_in_order_without_authority(self):
        a = definition("text", ParamKind.STRING)
        b = definition("number", ParamKind.NUMBER)
        batch = snapshot_exact_primitive_batch((
            (a, {"value": "synthetic"}),
            (b, {"value": 2}),
            (b, {"value": -1.5}),
        ))
        self.assertEqual(batch.count, 3)
        self.assertEqual([x.as_arguments()["value"] for x in batch.entries],
                         ["synthetic", 2, -1.5])
        self.assertFalse(batch.authorization_verified)
        self.assertFalse(batch.permit_issued)
        self.assertFalse(batch.execution_enabled)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_late_invalid_batch_fails_atomically(self):
        a = definition("text", ParamKind.STRING)
        b = definition("number", ParamKind.NUMBER)
        good = {"value": "safe"}
        late = {"value": FloatSubclass(2.25)}
        with self.assertRaises(OrchestrationError):
            snapshot_exact_primitive_batch(((a, good), (b, {"value": 1}), (b, late)))
        self.assertEqual(good, {"value": "safe"})
        self.assertIs(type(late["value"]), FloatSubclass)

    def test_batch_rejects_size_and_container_ambiguity(self):
        a = definition("text", ParamKind.STRING)
        item = (a, {"value": "ok"})
        for batch in ((), (item,) * (MAX_SYNTHETIC_BATCH_ITEMS + 1),
                      [item], (list(item),), ((a,),), ("bad",)):
            with self.subTest(shape=type(batch).__name__, length=len(batch)):
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_batch(batch)

    def test_caller_cannot_construct_or_flip_false_authority_flags(self):
        tool = definition("text", ParamKind.STRING)
        receipt = snapshot_exact_primitive_values(tool, {"value": "ok"})
        batch = snapshot_exact_primitive_batch(((tool, {"value": "ok"}),))
        for item in (receipt, batch):
            for flag in ("authorization_verified", "permit_issued", "execution_enabled"):
                with self.subTest(receipt=type(item).__name__, flag=flag):
                    self.assertFalse(getattr(item, flag))
                    with self.assertRaises(TypeError):
                        type(item)(**{
                            ("items" if item is receipt else "entries"):
                                (receipt.items if item is receipt else batch.entries),
                            flag: True,
                        })
                    with self.assertRaises((AttributeError, TypeError)):
                        object.__setattr__(item, flag, True)
                    self.assertFalse(getattr(item, flag))

    def test_batch_first_and_last_valid_bounds(self):
        tool = definition("text", ParamKind.STRING)
        self.assertEqual(snapshot_exact_primitive_batch(
            ((tool, {"value": "ok"}),)
        ).count, 1)
        self.assertEqual(snapshot_exact_primitive_batch(
            ((tool, {"value": "ok"}),) * MAX_SYNTHETIC_BATCH_ITEMS
        ).count, MAX_SYNTHETIC_BATCH_ITEMS)

    def test_cannot_preflight_active_or_passive_tools_even_with_valid_values(self):
        canonical = definition("text", ParamKind.STRING)
        for interaction, risk in (
            (InteractionKind.TARGET_ACTIVE, RiskLevel.STANDARD),
            (InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY),
            (InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE),
            (InteractionKind.ANALYSIS, RiskLevel.PASSIVE),
        ):
            with self.subTest(interaction=interaction.value, risk=int(risk)):
                changed = dataclasses.replace(
                    canonical, interaction=interaction, min_risk=risk
                )
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(changed, {"value": "safe"})
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_batch(((canonical, {"value": "ok"}),
                                                    (changed, {"value": "safe"})))

    def test_real_tool_names_cannot_masquerade_as_synthetic_preflight(self):
        canonical = definition("text", ParamKind.STRING)
        for tool_id in ("public-records", "service-probe", "synthetic-",
                        "", "Synthetic-probe"):
            with self.subTest(tool_id=tool_id):
                fake_name = dataclasses.replace(canonical, tool_id=tool_id)
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(fake_name, {"value": "ok"})

    def test_direct_receipt_constructor_rejects_type_confusion(self):
        valid = PrimitiveValueSnapshot((("value", "synthetic"),))
        self.assertEqual(valid.as_arguments(), {"value": "synthetic"})
        self.assertFalse(valid.permit_issued)
        for forged in (
            [("value", "synthetic")],
            (["value", "synthetic"],),
            (("value", StrSubclass("synthetic")),),
            ((StrSubclass("value"), "synthetic"),),
            (("value", object()),),
            (("value", 1), ("value", 2)),
            (("value",),),
            (("value", 1, 2),),
            (("value", "synthetic"),) * (MAX_SYNTHETIC_PARAMETERS + 1),
        ):
            with self.subTest(container=type(forged).__name__, length=len(forged)):
                with self.assertRaises(OrchestrationError):
                    PrimitiveValueSnapshot(forged)

    def test_direct_batch_constructor_rejects_noncanonical_entries(self):
        valid = PrimitiveValueSnapshot((("value", "ok"),))
        batch = PrimitiveBatchSnapshot((valid,))
        self.assertEqual(batch.count, 1)
        self.assertFalse(batch.authorization_verified)

        class SnapshotSubclass(PrimitiveValueSnapshot):
            pass

        child = SnapshotSubclass(valid.items)
        for forged in (
            [], (),
            [valid],
            ({"value": "ok"},),
            (child,),
            (valid,) * (MAX_SYNTHETIC_BATCH_ITEMS + 1),
        ):
            with self.subTest(type=type(forged).__name__, count=len(forged)):
                with self.assertRaises(OrchestrationError):
                    PrimitiveBatchSnapshot(forged)

    def test_direct_receipts_do_not_invoke_hostile_subclass_methods(self):
        class HostileValue(StrSubclass):
            def __str__(self):
                raise AssertionError("no conversion permitted")
            def __repr__(self):
                raise AssertionError("no custom repr permitted")
        with self.assertRaises(OrchestrationError):
            PrimitiveValueSnapshot((("value", HostileValue("never-used")),))
        with self.assertRaises(OrchestrationError):
            PrimitiveBatchSnapshot((object(),))

    def test_metadata_requires_exact_toolparameter_and_boolean_required(self):
        ordinary = definition("text", ParamKind.STRING)
        parameter = ordinary.parameters[0]

        class HostileParameter:
            @property
            def name(self):
                raise AssertionError("hostile metadata callback should not run")

        malicious = (
            HostileParameter(),
            dataclasses.replace(parameter, required=0),
            dataclasses.replace(parameter, required=""),
            dataclasses.replace(parameter, required=1),
            dataclasses.replace(parameter, name=StrSubclass("value")),
            dataclasses.replace(parameter, kind="string"),
        )
        for item in malicious:
            with self.subTest(type=type(item).__name__, required=repr(getattr(item, "required", None))):
                changed = dataclasses.replace(ordinary, parameters=(item,))
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(changed, {"value": "ok"})

    def test_parameter_container_must_be_exact_bounded_tuple(self):
        ordinary = definition("text", ParamKind.STRING)

        class TupleSubclass(tuple):
            pass

        for params in (
            list(ordinary.parameters),
            TupleSubclass(ordinary.parameters),
            (ordinary.parameters[0],) * (MAX_SYNTHETIC_PARAMETERS + 1),
        ):
            with self.subTest(container=type(params).__name__, count=len(params)):
                with self.assertRaises(OrchestrationError):
                    snapshot_exact_primitive_values(
                        dataclasses.replace(ordinary, parameters=params), {"value": "ok"}
                    )
        exactly_at_limit = dataclasses.replace(
            ordinary,
            parameters=tuple(
                ToolParameter("v" + str(i), ParamKind.INTEGER, required=False)
                for i in range(MAX_SYNTHETIC_PARAMETERS)
            ),
        )
        snap = snapshot_exact_primitive_values(exactly_at_limit, {})
        self.assertEqual(snap.items, ())

    def test_oversized_arguments_fail_before_unknown_key_processing(self):
        tool = definition("text", ParamKind.STRING)
        huge = {"value": "ok", **{"extra" + str(i): i for i in range(MAX_SYNTHETIC_PARAMETERS)}}
        with self.assertRaises(OrchestrationError):
            snapshot_exact_primitive_values(tool, huge)
        self.assertEqual(huge["value"], "ok")
        self.assertEqual(len(huge), MAX_SYNTHETIC_PARAMETERS + 1)

    def test_only_exact_tool_definition_accepted(self):
        class DefinitionChild(ToolDefinition):
            pass
        parent = definition("text", ParamKind.STRING)
        impostor = DefinitionChild(
            parent.tool_id, parent.capability_id, parent.interaction,
            parent.min_risk, parent.description, parent.parameters
        )
        with self.assertRaises(OrchestrationError):
            snapshot_exact_primitive_values(impostor, {"value": "ok"})


class SyntheticRealExecutorBatchTests(unittest.TestCase):
    """Actual SQLite + actual executor; dispatch happens only AFTER full preflight."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "optin-1095.sqlite")
        self.calls = []
        self.registry = ToolRegistry()
        self.text = definition("text", ParamKind.STRING)
        self.number = definition("number", ParamKind.NUMBER)
        self.registry.register(self.text, self.handler)
        self.registry.register(self.number, self.handler)
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext(
            run_id=str(uuid4()), client_id="synthetic-tenant",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def handler(self, context, arguments):
        self.calls.append(dict(arguments))
        return ToolOutput("synthetic, no target", "offline", b"synthetic only")

    def evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_late_invalid_rejected_without_any_dispatch_or_evidence(self):
        reqs = (
            (self.text, {"value": "synthetic"}),
            (self.number, {"value": 3}),
            (self.number, {"value": FloatSubclass(1.5)}),
        )
        before = self.evidence_count()
        with self.assertRaises(OrchestrationError):
            snapshot_exact_primitive_batch(reqs)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), before)

    def test_snapshot_used_for_synthetic_real_executor_and_immutable_values(self):
        args = {"value": "synthetic"}
        batch = snapshot_exact_primitive_batch(((self.text, args),
                                                (self.number, {"value": 2})))
        args["value"] = StrSubclass("not allowed")
        for tool, snap in zip((self.text, self.number), batch.entries):
            self.executor.execute(
                self.context,
                ToolCall(tool.tool_id, "synthetic.invalid",
                         arguments=snap.items),
            )
        self.assertEqual(self.calls, [{"value": "synthetic"}, {"value": 2}])
        self.assertEqual(self.evidence_count(), 2)
        self.assertFalse(batch.execution_enabled)

    def test_late_invalid_metadata_has_zero_handler_or_evidence_effect(self):
        good = (self.text, {"value": "ok"})
        bad = dataclasses.replace(
            self.number,
            parameters=(dataclasses.replace(
                self.number.parameters[0], required="truthy-but-not-bool"
            ),),
        )
        before = self.evidence_count()
        with self.assertRaises(OrchestrationError):
            snapshot_exact_primitive_batch((good, (bad, {"value": 3})))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), before)

    def test_preflight_does_not_invoke_registry_handlers_or_policy(self):
        batch = snapshot_exact_primitive_batch(((self.text, {"value": "ok"}),))
        self.assertEqual(batch.count, 1)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
