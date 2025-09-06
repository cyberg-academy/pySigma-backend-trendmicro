import pytest
from sigma.collection import SigmaCollection
from sigma.backends.trendmicro import TrendmicroVisionOneBackend

@pytest.fixture
def trendmicro_backend():
    return TrendmicroVisionOneBackend()

def test_trendmicro_windows_os_filter(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['eventId: "1" AND (osName: "Windows" AND processName: "valueA")']

def test_trendmicro_linux_os_filter(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['eventId: "1" AND (osName: "Linux" AND processName: "valueA")']

def test_trendmicro_osx_os_filter(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['eventId: "1" AND (osName: "macOS" AND processName: "valueA")']

def test_trendmicro_process_creation_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Signature: test_signature
                    OriginalFileName: original_file.exe
                    IntegrityLevel: bar bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    Domain: test_domain
                    ParentUser: parent_user
                    md5: asdfasdfasdfasdfasdf
                    sha1: asdfasdfasdfasdfasdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentIntegrityLevel: parent_integrity
                    ParentCommandLine: Get-Path
                    SourceIp: 192.168.1.1
                    SourceHostname: test_host
                    SourceId: source_123
                condition: sel
        """)
    ) == ['eventId: "1" AND (processPid: "12" AND processName: "valueA" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdfasdfasdf" AND processFileHashSha1: "asdfasdfasdfasdfasdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointIp: "192.168.1.1" AND endpointHostName: "test_host" AND endpointGuid: "source_123")']

def test_trendmicro_file_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: file_event
                    product: test_product
                detection:
                    sel:
                        Image: valueA
                        ProcessId: 12
                        Signature: test_signature
                        OriginalFileName: original_file.exe
                        IntegrityLevel: bar bar
                        Product: bar foo
                        Company: foo foo
                        CommandLine: invoke-mimikatz
                        CurrentDirectory: /etc
                        User: administrator
                        Domain: test_domain
                        ParentUser: parent_user
                        md5: asdfasdfasdfasdfasdf
                        sha1: asdfasdfasdfasdfasdfasdf
                        sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                        ParentProcessId: 13
                        ParentImage: valueB
                        ParentIntegrityLevel: parent_integrity
                        ParentCommandLine: Get-Path
                        SourceIp: 192.168.1.1
                        SourceHostname: test_host
                        SourceId: source_123
                    condition: sel
        """)
    ) == ['eventId: "2" AND (objectFilePath: "valueA" AND processPid: "12" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdfasdfasdf" AND processFileHashSha1: "asdfasdfasdfasdfasdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointIp: "192.168.1.1" AND endpointHostName: "test_host" AND endpointGuid: "source_123")']

def test_trendmicro_image_load_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: image_load
                product: test_product
            detection:
                sel:
                    ImageLoaded: foo bar
                    Image: valueA
                    ProcessId: 12
                    Signature: test_signature
                    OriginalFileName: original_file.exe
                    IntegrityLevel: bar bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    Domain: test_domain
                    ParentUser: parent_user
                    md5: asdfasdfasdf
                    sha1: asdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentIntegrityLevel: parent_integrity
                    ParentCommandLine: Get-Path
                    SourceIp: 192.168.1.1
                    SourceHostname: test_host
                    SourceId: source_123
                condition: sel
        """)
    ) == ['eventSubId: "4" AND (objectFilePath: "foo bar" AND processName: "valueA" AND processPid: "12" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdf" AND processFileHashSha1: "asdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointIp: "192.168.1.1" AND endpointHostName: "test_host" AND endpointGuid: "source_123")']

def test_trendmicro_registry_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
                    title: Test
                    status: test
                    logsource:
                        category: registry_event
                        product: test_product
                    detection:
                        sel:
                            ProcessId: 12
                            Image: valueA
                            Signature: test_signature
                            OriginalFileName: original_file.exe
                            IntegrityLevel: bar bar
                            Product: bar foo
                            Company: foo foo
                            CommandLine: invoke-mimikatz
                            CurrentDirectory: /etc
                            User: administrator
                            Domain: test_domain
                            ParentUser: parent_user
                            md5: asdfasdfasdf
                            sha1: asdfasdf
                            sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                            ParentProcessId: 13
                            ParentImage: valueB
                            ParentIntegrityLevel: parent_integrity
                            ParentCommandLine: Get-Path
                            SourceIp: 192.168.1.1
                            SourceHostname: test_host
                            SourceId: source_123
                            TargetObject: foo bar
                            Details: bar foo
                            Key: test_key
                            Data: test_data
                            Value: test_value
                        condition: sel
                """)
    ) == [
        'eventId: "5" AND (processPid: "12" AND processName: "valueA" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdf" AND processFileHashSha1: "asdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointIp: "192.168.1.1" AND endpointHostName: "test_host" AND endpointGuid: "source_123" AND objectRegistryKeyHandle: "foo bar" AND objectRegistryData: "bar foo" AND objectRegistryKeyHandle: "test_key" AND objectRegistryData: "test_data" AND objectRegistryValue: "test_value")'
    ]

def test_trendmicro_dns_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: dns
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Signature: test_signature
                    OriginalFileName: original_file.exe
                    IntegrityLevel: bar bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    Domain: test_domain
                    ParentUser: parent_user
                    md5: asdfasdfasdf
                    sha1: asdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentIntegrityLevel: parent_integrity
                    ParentCommandLine: Get-Path
                    SourceIp: 1.1.1.1
                    DestinationIp: 0.0.0.0
                    SourceHostname: test_host
                    SourceId: source_123
                    query: foo bar
                    answer: bar foo
                    QueryName: foo foo
                condition: sel
        """)
    ) == ['eventId: "4" AND (processPid: "12" AND processName: "valueA" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdf" AND processFileHashSha1: "asdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointIp: "1.1.1.1" AND objectIps: "0.0.0.0" AND endpointHostName: "test_host" AND endpointGuid: "source_123" AND hostName: "foo bar" AND objectIps: "bar foo" AND hostName: "foo foo")']

def test_trendmicro_network_mapping(trendmicro_backend : TrendmicroVisionOneBackend):
    assert trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Signature: test_signature
                    OriginalFileName: original_file.exe
                    IntegrityLevel: bar bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    Domain: test_domain
                    ParentUser: parent_user
                    md5: asdfasdfasdf
                    sha1: asdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentIntegrityLevel: parent_integrity
                    ParentCommandLine: Get-Path
                    SourceHostname: test_host
                    SourceId: source_123
                    DestinationHostname: foo bar
                    DestinationPort: 445
                    DestinationIp: 0.0.0.0
                    SourceIp: 1.1.1.1
                    SourcePort: 135
                    dst_ip: 2.2.2.2
                    src_ip: 3.3.3.3
                    dst_port: 80
                    src_port: 8080
                condition: sel
        """)
    ) == ['(eventId IN ("3","4","7")) AND (processPid: "12" AND processName: "valueA" AND processSigner: "test_signature" AND objectFilePath: "original_file.exe" AND integrityLevel: "bar bar" AND processSigner: "bar foo" AND processSigner: "foo foo" AND processCmd: "invoke-mimikatz" AND processFilePath: "/etc" AND processUser: "administrator" AND userDomain: "test_domain" AND parentUser: "parent_user" AND processFileHashMd5: "asdfasdfasdf" AND processFileHashSha1: "asdfasdf" AND processFileHashSha256: "asdfasdfasdfasdfasdfasdfasdfasdf" AND parentPid: "13" AND parentFilePath: "valueB" AND parentIntegrityLevel: "parent_integrity" AND parentCmd: "Get-Path" AND endpointHostName: "test_host" AND endpointGuid: "source_123" AND hostName: "foo bar" AND dpt: "445" AND dst: "0.0.0.0" AND src: "1.1.1.1" AND spt: "135" AND dst: "2.2.2.2" AND src: "3.3.3.3" AND dpt: "80" AND spt: "8080")']

def test_trendmicro_unsupported_rule_type(trendmicro_backend : TrendmicroVisionOneBackend):
  with pytest.raises(ValueError):
    trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_trendmicro_unsupported_field_name(trendmicro_backend : TrendmicroVisionOneBackend):
  with pytest.raises(ValueError):
    trendmicro_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )