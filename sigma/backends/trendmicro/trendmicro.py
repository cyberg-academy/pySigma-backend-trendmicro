import re
from typing import ClassVar, Dict, List, Pattern, Tuple, Union

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression

from sigma.pipelines.trendmicro import trendmicro_pipeline


class TrendmicroVisionOneBackend(TextQueryBackend):
    """Trendmicro Vision One backend.
    - Syntax doc ref: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-search-syntax
    """

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = trendmicro_pipeline()

    name: ClassVar[str] = "Trendmicro Vision One backend"
    formats: Dict[str, str] = {"default": "Plaintext", "json": "JSON format"}

    requires_pipeline: bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    parenthesize: bool = True
    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = ": "

    field_quote: ClassVar[str] = "'"
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")
    field_quote_pattern_negation: ClassVar[bool] = True

    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = ""
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    startswith_expression: ClassVar[str] = "{field}: startswith {value}"
    endswith_expression: ClassVar[str] = "{field}: endswith {value}"
    contains_expression: ClassVar[str] = "{field}: contains {value}"

    re_expression: ClassVar[str] = "{field}: /{regex}/"
    re_escape_char: ClassVar[str] = "\\/"
    re_escape: ClassVar[Tuple[str]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = False

    compare_op_expression: ClassVar[str] = '{field} {operator} "{value}"'
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "{field} IS NOT EMPTY"

    field_exists_expression: ClassVar[str] = (
        "{field} EXISTS"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "{field} DOES NOT EXIST"
        # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False
        # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"
        # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "IN"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    list_separator: ClassVar[str] = ","  # List element separator

    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = '"{value}"'

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions
        In Trendmicro Vision One, number fields must be treated as strings and quoted
        """
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + '"' + str(cond.value) + '"'
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # Starts/Endswith ñapa
        # As cortex does not have endswith/startswith operators, we need to replace them with regex
        def transform_query(query: str) -> str:
            """
            Rewrite occurrences of:
              - contains "foo"   → "*foo*"
              - startswith "foo" → "foo*"
              - endswith "foo"   → "*foo"
            while leaving everything else untouched.
            """

            def _repl(m: re.Match) -> str:
                op, val = m.group(1), m.group(2)
                if op == "contains":
                    return f'"*{val}*"'
                elif op == "startswith":
                    return f'"{val}*"'
                else:  # op == "endswith"
                    return f'"*{val}"'

            # match the operator and its quoted argument
            pattern = r'\b(contains|startswith|endswith)\s+"([^"]+)"'
            return re.sub(pattern, _repl, query)

        final_query = transform_query(query)
        return final_query

    def finalize_output_default(self, queries: List[str]) -> str:
        return queries

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> dict:
        return {
            "query": query,
            "title": rule.title,
            "id": rule.id,
            "description": rule.description,
        }

    def finalize_output_json(self, queries: List[str]) -> dict:
        return {"queries": queries}
