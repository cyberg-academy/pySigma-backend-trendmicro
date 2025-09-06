from sigma.exceptions import SigmaTransformationError
from sigma.processing.conditions import (
    ExcludeFieldCondition,
    LogsourceCondition,
    RuleProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ChangeLogsourceTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
)
from sigma.rule import SigmaDetectionItem


class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)


def _flatten(items, seqtypes=(list, tuple)):
    """Private function to flatten lists for Field mapping errors"""
    try:
        for i, x in enumerate(items):
            while isinstance(items[i], seqtypes):
                items[i : i + 1] = items[i]
    except IndexError:
        pass
    return items


def trendmicro_pipeline() -> ProcessingPipeline:
    """
    The pipeline is focused on table: endpointActivities
        - endpointActivities fields: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-endpoint-activity-data

    All tables available:
        - endpointActivities
        - cloudActivities
        - emailActivities
        - networkActivities
        - mobileActivities
        - containerActivities
        - identityActivities
        - activityStatistics
        - sensorActivities
    """

    general_supported_fields = [
        "eventId",
        "eventSubId",
        "osName",
    ]

    translation_dict = {
        "process_creation": {
            "ProcessId": "processPid",
            "Image": "processName",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceIp": "endpointIp",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
        },
        "file": {
            "Image": "objectFilePath",
            "ProcessId": "processPid",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceIp": "endpointIp",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
        },
        "image_load": {
            "ImageLoaded": "objectFilePath",
            "Image": "processName",
            "ProcessId": "processPid",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceIp": "endpointIp",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
        },
        # Not observed
        # "pipe_creation": {
        #     "PipeName": "NamedPipeName",
        #     "Image": "SrcProcImagePath",
        #     "CommandLine": "SrcProcCmdLine",
        #     "ParentImage": "SrcProcParentImagePath",
        #     "ParentCommandLine": "SrcProcParentCmdline",
        # },
        "registry": {
            "ProcessId": "processPid",
            "Image": "processName",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceIp": "endpointIp",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
            "TargetObject": "objectRegistryKeyHandle",
            "Details": "objectRegistryData",
            "Key": "objectRegistryKeyHandle",
            "Data": "objectRegistryData",
            "Value": "objectRegistryValue",
        },
        "dns": {
            "ProcessId": "processPid",
            "Image": "processName",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceIp": "endpointIp",
            "DestinationIp": "objectIps",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
            "query": "hostName",
            "answer": "objectIps",
            "QueryName": "hostName",
        },
        "network": {
            "ProcessId": "processPid",
            "Image": "processName",
            "Signature": "processSigner",
            "OriginalFileName": "objectFilePath",
            "IntegrityLevel": "integrityLevel",
            "Product": "processSigner",
            "Company": "processSigner",
            "CommandLine": "processCmd",
            "CurrentDirectory": "processFilePath",
            "User": "processUser",
            "Domain": "userDomain",
            "ParentUser": "parentUser",
            "md5": "processFileHashMd5",
            "sha1": "processFileHashSha1",
            "sha256": "processFileHashSha256",
            "ParentProcessId": "parentPid",
            "ParentImage": "parentFilePath",
            "ParentIntegrityLevel": "parentIntegrityLevel",
            "ParentCommandLine": "parentCmd",
            "SourceHostname": "endpointHostName",
            "SourceId": "endpointGuid",
            "DestinationHostname": "hostName",
            "DestinationPort": "dpt",
            "DestinationIp": "dst",
            "SourceIp": "src",
            "SourcePort": "spt",
            "dst_ip": "dst",
            "src_ip": "src",
            "dst_port": "dpt",
            "src_port": "spt",
        },
    }

    os_filter = [
        # Linux
        ProcessingItem(
            identifier="tm_linux_product",
            transformation=AddConditionTransformation({"osName": "Linux"}),
            rule_conditions=[LogsourceCondition(product="linux")],
        ),
        # Windows
        ProcessingItem(
            identifier="tm_windows_product",
            transformation=AddConditionTransformation({"osName": "Windows"}),
            rule_conditions=[LogsourceCondition(product="windows")],
        ),
        # macOS
        ProcessingItem(
            identifier="tm_osx_product",
            transformation=AddConditionTransformation({"osName": "macOS"}),
            rule_conditions=[LogsourceCondition(product="macos")],
        ),
    ]

    # https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-eventid-eventsubid-mapping
    object_event_type_filter = [
        ProcessingItem(
            identifier="tm_process_creation_eventtype",
            transformation=AddConditionTransformation({"eventId": "1"}),
            rule_conditions=[LogsourceCondition(category="process_creation")],
        ),
        ProcessingItem(
            identifier="tm_file_event_objecttype",
            transformation=AddConditionTransformation({"eventId": "2"}),
            rule_conditions=[LogsourceCondition(category="file_event")],
        ),
        ProcessingItem(
            identifier="tm_file_change_eventtype",
            transformation=AddConditionTransformation({"eventSubId": "109"}),
            rule_conditions=[LogsourceCondition(category="file_change")],
        ),
        ProcessingItem(
            identifier="tm_file_rename_eventtype",
            transformation=AddConditionTransformation({"eventSubId": "110"}),
            rule_conditions=[LogsourceCondition(category="file_rename")],
        ),
        ProcessingItem(
            identifier="tm_file_delete_eventtype",
            transformation=AddConditionTransformation({"eventSubId": "103"}),
            rule_conditions=[LogsourceCondition(category="file_delete")],
        ),
        ProcessingItem(
            identifier="tm_image_load_eventtype",
            transformation=AddConditionTransformation({"eventSubId": "4"}),
            rule_conditions=[LogsourceCondition(category="image_load")],
        ),
        # ProcessingItem(
        #     identifier="tm_pipe_creation_eventtype",
        #     transformation=AddConditionTransformation({"eventId": "17"}),
        #     rule_conditions=[LogsourceCondition(category="pipe_creation")],
        # ),
        ProcessingItem(
            identifier="tm_registry_eventtype",
            transformation=AddConditionTransformation({"eventId": "5"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
            ],
        ),
        ProcessingItem(
            identifier="tm_dns_objecttype",
            transformation=AddConditionTransformation({"eventId": "4"}),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns"),
            ],
        ),
        ProcessingItem(
            identifier="tm_network_objecttype",
            transformation=AddConditionTransformation({"eventId": ["3", "4", "7"]}),
            rule_conditions=[LogsourceCondition(category="network_connection")],
        ),
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="tm_process_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["process_creation"]),
            rule_conditions=[LogsourceCondition(category="process_creation")],
        ),
        # File Stuff
        ProcessingItem(
            identifier="tm_file_change_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["file"]),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
            ],
        ),
        # Module Load Stuff
        ProcessingItem(
            identifier="tm_image_load_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["image_load"]),
            rule_conditions=[LogsourceCondition(category="image_load")],
        ),
        # Pipe Creation Stuff
        # ProcessingItem(
        #     identifier="tm_pipe_creation_fieldmapping",
        #     transformation=FieldMappingTransformation(translation_dict["pipe_creation"]),
        #     rule_conditions=[LogsourceCondition(category="pipe_creation")],
        # ),
        # Registry Stuff
        ProcessingItem(
            identifier="tm_registry_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["registry"]),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
            ],
        ),
        # DNS Stuff
        ProcessingItem(
            identifier="tm_dns_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["dns"]),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="dns"),
            ],
        ),
        # Network Stuff
        ProcessingItem(
            identifier="tm_network_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict["network"]),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall"),
            ],
        ),
    ]

    change_logsource_info = [
        ProcessingItem(
            identifier="tm_logsource",
            transformation=ChangeLogsourceTransformation(service="trendmicro"),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                # LogsourceCondition(category="pipe_creation"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="dns"),
                LogsourceCondition(category="dns_query"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall"),
            ],
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="tm_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation(
                "Rule type not yet supported by the Trendmicro VisionOne Sigma backend"
            ),
            rule_condition_negation=True,
            rule_conditions=[RuleProcessingItemAppliedCondition("tm_logsource")],
        )
    ]

    unsupported_field_name = [
        ProcessingItem(
            identifier="tm_fail_field_not_supported",
            transformation=InvalidFieldTransformation(
                "This pipeline only supports the following fields:\n{"
                + "}, {".join(
                    sorted(
                        set(
                            list(
                                _flatten(
                                    [[k, v] for t in translation_dict.keys() for k, v in translation_dict[t].items()]
                                )
                            )
                            + general_supported_fields
                        )
                    )
                )
            ),
            field_name_conditions=[
                ExcludeFieldCondition(
                    fields=list(
                        set(
                            list(
                                _flatten(
                                    [[k, v] for t in translation_dict.keys() for k, v in translation_dict[t].items()]
                                )
                            )
                            + general_supported_fields
                        )
                    )
                )
            ],
        )
    ]

    return ProcessingPipeline(
        name="Trendmicro VisionOne pipeline",
        priority=50,
        items=[
            *unsupported_field_name,
            *os_filter,
            *object_event_type_filter,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types,
        ],
    )
