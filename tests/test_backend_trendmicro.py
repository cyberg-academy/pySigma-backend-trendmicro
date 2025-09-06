import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.backends.trendmicro import TrendmicroVisionOneBackend
from sigma.pipelines.trendmicro import trendmicro_pipeline


@pytest.fixture
def trendmicro_backend():
    return TrendmicroVisionOneBackend()

def test_trendmicro_and_expression(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['eventId: "1" AND (processName: "valueA" AND parentFilePath: "valueB")']

def test_trendmicro_or_expression(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA
                sel2:
                    ParentImage: valueB
                condition: 1 of sel*
        """)
    ) == ['eventId: "1" AND (processName: "valueA" OR parentFilePath: "valueB")']

def test_trendmicro_and_or_expression(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['eventId: "1" AND ((processName IN ("valueA1","valueA2")) AND (parentFilePath IN ("valueB1","valueB2")))']

def test_trendmicro_or_and_expression(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['eventId: "1" AND ((processName: "valueA1" AND parentFilePath: "valueB1") OR (processName: "valueA2" AND parentFilePath: "valueB2"))']

def test_trendmicro_in_expression(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['eventId: "1" AND (processName: "valueA" OR processName: "valueB" OR processName: "valueC*")']

def test_trendmicro_regex_query(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['eventId: "1" AND (processName: /foo.*bar/ AND parentFilePath: "foo")']

def test_trendmicro_cidr_query(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    DestinationIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['(eventId IN ("3","4","7")) AND dst: "192.168.*"']

def test_trendmicro_default_output(trendmicro_backend : TrendmicroVisionOneBackend):
    """Test for output format default."""
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['eventId: "1" AND processName: "valueA"']

def test_trendmicro_preapply_pipeline(trendmicro_backend: TrendmicroVisionOneBackend):
    """Tests for pre-applying the TrendMicro pipeline prior to converting a rule in the backend"""
    sigma_rule = SigmaRule.from_yaml("""
        title: Test
        status: test
        logsource:
            category: process_creation
            product: test_product
        detection:
            sel:
                Image: valueA
                ParentImage: valueB
            condition: sel
    """)
    trendmicro_pipeline().apply(sigma_rule)
    assert trendmicro_backend.convert_rule(
        sigma_rule
    ) == ['eventId: "1" AND (processName: "valueA" AND parentFilePath: "valueB")']
