#!/usr/bin/env python3
"""
cloud_scan.py - AWS Cloud Resource Scanner for Miro Cloud Data Import

Produces JSON output compatible with @mirohq/cloud-data-import (docVersion 0.1.5).

Usage:
    python cloud_scan.py --profile myprofile --regions us-east-1 us-west-2
    python cloud_scan.py --regions all
    python cloud_scan.py --profile myprofile --regions us-east-1 --raw --output scan.json

Requirements:
    pip install boto3
"""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import boto3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_REGIONS = [
    "us-east-2", "us-east-1", "us-west-1", "us-west-2",
    "af-south-1", "ap-east-1", "ap-south-2", "ap-southeast-3",
    "ap-southeast-4", "ap-south-1", "ap-northeast-3", "ap-northeast-2",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ca-central-1", "ca-west-1",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1",
    "eu-west-3", "eu-south-2", "eu-north-1", "eu-central-2",
    "il-central-1", "me-south-1", "me-central-1", "sa-east-1",
    "us-gov-east-1", "us-gov-west-1",
]

TAGGING_RESOURCE_TYPES = [
    "athena:named-query", "autoscaling:group", "cloudtrail:trail",
    "cloudwatch:alarm", "cloudwatch:metric-stream", "dynamodb:table",
    "ec2:instance", "ec2:vpc", "ec2:vpc-endpoint", "ec2:subnet",
    "ec2:route-table", "ec2:internet-gateway", "ec2:nat-gateway",
    "ec2:transit-gateway", "ec2:volume", "ec2:network-acl",
    "ec2:vpn-gateway", "ec2:network-interface",
    "ecs:cluster", "ecs:service", "ecs:task",
    "elasticfilesystem:file-system",
    "elasticache:cluster", "elasticache:replicationgroup",
    "elasticloadbalancing:loadbalancer", "elasticloadbalancing:targetgroup",
    "eks:cluster", "lambda:function", "es:domain",
    "redshift:cluster", "rds:db", "rds:cluster", "rds:proxy",
    "s3:bucket", "sns:topic", "sqs:queue",
    "route53:hostedzone", "cloudfront:distribution",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_arn(service: str, region: str, account: str, resource: str) -> str:
    return f"arn:aws:{service}:{region}:{account}:{resource}"


def parse_arn(arn: str) -> dict:
    """Parse an ARN into its components."""
    parts = arn.split(":")
    if len(parts) < 6:
        return {"partition": "", "service": "", "region": "", "account": "", "resource": arn}
    resource = ":".join(parts[5:])
    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account": parts[4],
        "resource": resource,
    }


def get_type_from_arn(service: str, resource: str) -> str:
    if service == "sns":
        return "topic"
    if service == "sqs":
        return "queue"
    return resource.split("/")[0].split(":")[0]


def get_name_from_arn(resource_full: str, resource_type: str) -> str:
    if resource_full.startswith(resource_type):
        return resource_full[len(resource_type) + 1:]
    return resource_full


def json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def log(msg: str) -> None:
    print(f"  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Session / client helpers
# ---------------------------------------------------------------------------

_sessions: dict[str, boto3.Session] = {}


def get_session(profile: str | None, region: str | None = None) -> boto3.Session:
    key = f"{profile}:{region}"
    if key not in _sessions:
        kwargs: dict[str, Any] = {}
        if profile:
            kwargs["profile_name"] = profile
        if region:
            kwargs["region_name"] = region
        _sessions[key] = boto3.Session(**kwargs)
    return _sessions[key]


def get_account_id(profile: str | None) -> str:
    session = get_session(profile)
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


# ---------------------------------------------------------------------------
# Resource scanners
# ---------------------------------------------------------------------------

def scan_ec2_instances(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                iid = inst.get("InstanceId", "")
                if iid:
                    arn = build_arn("ec2", region, account, f"instance/{iid}")
                    resources[arn] = inst
    return resources


def scan_ec2_vpcs(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for vpc in ec2.describe_vpcs().get("Vpcs", []):
        vid = vpc.get("VpcId", "")
        if vid:
            arn = build_arn("ec2", region, account, f"vpc/{vid}")
            resources[arn] = vpc
    return resources


def scan_ec2_subnets(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for sub in ec2.describe_subnets().get("Subnets", []):
        sid = sub.get("SubnetId", "")
        if sid:
            arn = build_arn("ec2", region, account, f"subnet/{sid}")
            resources[arn] = sub
    return resources


def scan_ec2_route_tables(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for rt in ec2.describe_route_tables().get("RouteTables", []):
        rid = rt.get("RouteTableId", "")
        if rid:
            arn = build_arn("ec2", region, account, f"route-table/{rid}")
            resources[arn] = rt
    return resources


def scan_ec2_internet_gateways(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for igw in ec2.describe_internet_gateways().get("InternetGateways", []):
        gid = igw.get("InternetGatewayId", "")
        if gid:
            arn = build_arn("ec2", region, account, f"internet-gateway/{gid}")
            resources[arn] = igw
    return resources


def scan_ec2_nat_gateways(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_nat_gateways")
    for page in paginator.paginate():
        for ngw in page.get("NatGateways", []):
            nid = ngw.get("NatGatewayId", "")
            if nid:
                arn = build_arn("ec2", region, account, f"nat-gateway/{nid}")
                resources[arn] = ngw
    return resources


def scan_ec2_transit_gateways(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_transit_gateways")
    for page in paginator.paginate():
        for tgw in page.get("TransitGateways", []):
            arn = tgw.get("TransitGatewayArn", "")
            if arn:
                resources[arn] = tgw
    return resources


def scan_ec2_volumes(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page.get("Volumes", []):
            vid = vol.get("VolumeId", "")
            if vid:
                arn = build_arn("ec2", region, account, f"volume/{vid}")
                resources[arn] = vol
    return resources


def scan_ec2_network_acls(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for nacl in ec2.describe_network_acls().get("NetworkAcls", []):
        nid = nacl.get("NetworkAclId", "")
        if nid:
            arn = build_arn("ec2", region, account, f"network-acl/{nid}")
            resources[arn] = nacl
    return resources


def scan_ec2_vpn_gateways(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    for vgw in ec2.describe_vpn_gateways().get("VpnGateways", []):
        vid = vgw.get("VpnGatewayId", "")
        if vid:
            arn = build_arn("ec2", region, account, f"vpn-gateway/{vid}")
            resources[arn] = vgw
    return resources


def scan_ec2_vpc_endpoints(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate():
        for ep in page.get("VpcEndpoints", []):
            eid = ep.get("VpcEndpointId", "")
            if eid:
                arn = build_arn("ec2", region, account, f"vpc-endpoint/{eid}")
                resources[arn] = ep
    return resources


def scan_ec2_network_interfaces(session: boto3.Session, region: str, account: str) -> dict:
    ec2 = session.client("ec2", region_name=region)
    resources = {}
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        for eni in page.get("NetworkInterfaces", []):
            nid = eni.get("NetworkInterfaceId", "")
            if nid:
                arn = build_arn("ec2", region, account, f"network-interface/{nid}")
                resources[arn] = eni
    return resources


def scan_lambda_functions(session: boto3.Session, region: str, _account: str) -> dict:
    lam = session.client("lambda", region_name=region)
    resources = {}
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            arn = fn.get("FunctionArn", "")
            if arn:
                resources[arn] = fn
    return resources


def scan_s3_buckets(session: boto3.Session, _region: str, account: str) -> dict:
    s3 = session.client("s3")
    resources = {}
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket.get("Name", "")
        if not name:
            continue
        arn = f"arn:aws:s3:::{name}"
        try:
            loc_resp = s3.get_bucket_location(Bucket=name)
            location = loc_resp.get("LocationConstraint") or "us-east-1"
        except Exception:
            location = "us-east-1"
        bucket["Account"] = account
        bucket["Location"] = location
        resources[arn] = bucket
    return resources


def scan_dynamodb_tables(session: boto3.Session, region: str, _account: str) -> dict:
    ddb = session.client("dynamodb", region_name=region)
    resources = {}
    paginator = ddb.get_paginator("list_tables")
    for page in paginator.paginate():
        for table_name in page.get("TableNames", []):
            try:
                desc = ddb.describe_table(TableName=table_name)["Table"]
                arn = desc.get("TableArn", "")
                if arn:
                    resources[arn] = desc
            except Exception:
                pass
    return resources


def scan_rds_instances(session: boto3.Session, region: str, _account: str) -> dict:
    rds = session.client("rds", region_name=region)
    resources = {}
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            arn = db.get("DBInstanceArn", "")
            if arn:
                resources[arn] = db
    return resources


def scan_rds_clusters(session: boto3.Session, region: str, _account: str) -> dict:
    rds = session.client("rds", region_name=region)
    resources = {}
    paginator = rds.get_paginator("describe_db_clusters")
    for page in paginator.paginate():
        for cluster in page.get("DBClusters", []):
            arn = cluster.get("DBClusterArn", "")
            if arn:
                resources[arn] = cluster
    return resources


def scan_rds_proxies(session: boto3.Session, region: str, _account: str) -> dict:
    rds = session.client("rds", region_name=region)
    resources = {}
    try:
        paginator = rds.get_paginator("describe_db_proxies")
        for page in paginator.paginate():
            for proxy in page.get("DBProxies", []):
                arn = proxy.get("DBProxyArn", "")
                if arn:
                    resources[arn] = proxy
    except Exception:
        pass
    return resources


def scan_ecs_clusters(session: boto3.Session, region: str, _account: str) -> dict:
    ecs = session.client("ecs", region_name=region)
    resources = {}
    cluster_arns = []
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        cluster_arns.extend(page.get("clusterArns", []))
    if cluster_arns:
        # describe_clusters supports max 100 at a time
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i:i + 100]
            desc = ecs.describe_clusters(clusters=batch, include=["TAGS", "SETTINGS", "STATISTICS"])
            for cluster in desc.get("clusters", []):
                arn = cluster.get("clusterArn", "")
                if arn:
                    resources[arn] = cluster
    return resources


def scan_ecs_services(session: boto3.Session, region: str, _account: str) -> dict:
    ecs = session.client("ecs", region_name=region)
    resources = {}
    cluster_arns = []
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        cluster_arns.extend(page.get("clusterArns", []))
    for cluster_arn in cluster_arns:
        svc_arns = []
        svc_paginator = ecs.get_paginator("list_services")
        for page in svc_paginator.paginate(cluster=cluster_arn):
            svc_arns.extend(page.get("serviceArns", []))
        if svc_arns:
            for i in range(0, len(svc_arns), 10):
                batch = svc_arns[i:i + 10]
                desc = ecs.describe_services(cluster=cluster_arn, services=batch)
                for svc in desc.get("services", []):
                    arn = svc.get("serviceArn", "")
                    if arn:
                        resources[arn] = svc
    return resources


def scan_ecs_tasks(session: boto3.Session, region: str, _account: str) -> dict:
    ecs = session.client("ecs", region_name=region)
    resources = {}
    cluster_arns = []
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        cluster_arns.extend(page.get("clusterArns", []))
    for cluster_arn in cluster_arns:
        task_arns = []
        task_paginator = ecs.get_paginator("list_tasks")
        for page in task_paginator.paginate(cluster=cluster_arn):
            task_arns.extend(page.get("taskArns", []))
        if task_arns:
            for i in range(0, len(task_arns), 100):
                batch = task_arns[i:i + 100]
                desc = ecs.describe_tasks(cluster=cluster_arn, tasks=batch)
                for task in desc.get("tasks", []):
                    arn = task.get("taskArn", "")
                    if arn:
                        resources[arn] = task
    return resources


def scan_eks_clusters(session: boto3.Session, region: str, _account: str) -> dict:
    eks = session.client("eks", region_name=region)
    resources = {}
    paginator = eks.get_paginator("list_clusters")
    for page in paginator.paginate():
        for name in page.get("clusters", []):
            try:
                desc = eks.describe_cluster(name=name)["cluster"]
                arn = desc.get("arn", "")
                if arn:
                    resources[arn] = desc
            except Exception:
                pass
    return resources


def scan_efs_file_systems(session: boto3.Session, region: str, _account: str) -> dict:
    efs = session.client("efs", region_name=region)
    resources = {}
    paginator = efs.get_paginator("describe_file_systems")
    for page in paginator.paginate():
        for fs in page.get("FileSystems", []):
            arn = fs.get("FileSystemArn", "")
            if arn:
                resources[arn] = fs
    return resources


def scan_elasticache_clusters(session: boto3.Session, region: str, _account: str) -> dict:
    ec = session.client("elasticache", region_name=region)
    resources = {}
    paginator = ec.get_paginator("describe_cache_clusters")
    for page in paginator.paginate():
        for cluster in page.get("CacheClusters", []):
            arn = cluster.get("ARN", "")
            if arn:
                resources[arn] = cluster
    return resources


def scan_elasticache_replication_groups(session: boto3.Session, region: str, _account: str) -> dict:
    ec = session.client("elasticache", region_name=region)
    resources = {}
    paginator = ec.get_paginator("describe_replication_groups")
    for page in paginator.paginate():
        for rg in page.get("ReplicationGroups", []):
            arn = rg.get("ARN", "")
            if arn:
                resources[arn] = rg
    return resources


def scan_elbv2_load_balancers(session: boto3.Session, region: str, _account: str) -> dict:
    elb = session.client("elbv2", region_name=region)
    resources = {}
    paginator = elb.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancers", []):
            arn = lb.get("LoadBalancerArn", "")
            if arn:
                resources[arn] = lb
    return resources


def scan_elbv2_target_groups(session: boto3.Session, region: str, _account: str) -> dict:
    elb = session.client("elbv2", region_name=region)
    resources = {}
    paginator = elb.get_paginator("describe_target_groups")
    for page in paginator.paginate():
        for tg in page.get("TargetGroups", []):
            arn = tg.get("TargetGroupArn", "")
            if arn:
                resources[arn] = tg
    return resources


def scan_elbv1_load_balancers(session: boto3.Session, region: str, account: str) -> dict:
    elb = session.client("elb", region_name=region)
    resources = {}
    paginator = elb.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancerDescriptions", []):
            name = lb.get("LoadBalancerName", "")
            if name:
                arn = build_arn("elasticloadbalancing", region, account, f"loadbalancer/{name}")
                resources[arn] = lb
    return resources


def scan_cloudfront_distributions(session: boto3.Session, _region: str, _account: str) -> dict:
    cf = session.client("cloudfront")
    resources = {}
    paginator = cf.get_paginator("list_distributions")
    for page in paginator.paginate():
        dist_list = page.get("DistributionList") or {}
        for dist in dist_list.get("Items", []):
            arn = dist.get("ARN", "")
            if arn:
                resources[arn] = dist
    return resources


def scan_route53_hosted_zones(session: boto3.Session, _region: str, account: str) -> dict:
    r53 = session.client("route53")
    resources = {}
    paginator = r53.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for zone in page.get("HostedZones", []):
            zone_id = zone.get("Id", "").replace("/hostedzone/", "")
            if zone_id:
                arn = f"arn:aws:route53::{account}:hostedzone/{zone_id}"
                zone["Account"] = account
                resources[arn] = zone
    return resources


def scan_sns_topics(session: boto3.Session, region: str, _account: str) -> dict:
    sns = session.client("sns", region_name=region)
    resources = {}
    paginator = sns.get_paginator("list_topics")
    for page in paginator.paginate():
        for topic in page.get("Topics", []):
            arn = topic.get("TopicArn", "")
            if arn:
                resources[arn] = topic
    return resources


def scan_sqs_queues(session: boto3.Session, region: str, _account: str) -> dict:
    sqs = session.client("sqs", region_name=region)
    resources = {}
    paginator = sqs.get_paginator("list_queues")
    for page in paginator.paginate():
        for url in page.get("QueueUrls", []):
            try:
                attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])
                queue_attrs = attrs.get("Attributes", {})
                arn = queue_attrs.get("QueueArn", "")
                if arn:
                    resources[arn] = queue_attrs
            except Exception:
                pass
    return resources


def scan_cloudtrail_trails(session: boto3.Session, region: str, _account: str) -> dict:
    ct = session.client("cloudtrail", region_name=region)
    resources = {}
    for trail in ct.describe_trails().get("trailList", []):
        arn = trail.get("TrailARN", "")
        # Filter to trails homed in this region to avoid duplicates across regions
        if arn and trail.get("HomeRegion", region) == region:
            resources[arn] = trail
    return resources


def scan_cloudwatch_metric_alarms(session: boto3.Session, region: str, _account: str) -> dict:
    cw = session.client("cloudwatch", region_name=region)
    resources = {}
    paginator = cw.get_paginator("describe_alarms")
    for page in paginator.paginate():
        for alarm in page.get("MetricAlarms", []):
            arn = alarm.get("AlarmArn", "")
            if arn:
                resources[arn] = alarm
    return resources


def scan_cloudwatch_metric_streams(session: boto3.Session, region: str, _account: str) -> dict:
    cw = session.client("cloudwatch", region_name=region)
    resources = {}
    try:
        paginator = cw.get_paginator("list_metric_streams")
        for page in paginator.paginate():
            for stream in page.get("Entries", []):
                arn = stream.get("Arn", "")
                if arn:
                    resources[arn] = stream
    except Exception:
        pass
    return resources


def scan_autoscaling_groups(session: boto3.Session, region: str, _account: str) -> dict:
    asg = session.client("autoscaling", region_name=region)
    resources = {}
    paginator = asg.get_paginator("describe_auto_scaling_groups")
    for page in paginator.paginate():
        for group in page.get("AutoScalingGroups", []):
            arn = group.get("AutoScalingGroupARN", "")
            if arn:
                resources[arn] = group
    return resources


def scan_athena_named_queries(session: boto3.Session, region: str, account: str) -> dict:
    athena = session.client("athena", region_name=region)
    resources = {}
    query_ids = []
    paginator = athena.get_paginator("list_named_queries")
    for page in paginator.paginate():
        query_ids.extend(page.get("NamedQueryIds", []))
    if query_ids:
        for i in range(0, len(query_ids), 50):
            batch = query_ids[i:i + 50]
            resp = athena.batch_get_named_query(NamedQueryIds=batch)
            for nq in resp.get("NamedQueries", []):
                nq_id = nq.get("NamedQueryId", "")
                if nq_id:
                    workgroup = nq.get("WorkGroup", "primary")
                    arn = build_arn("athena", region, account, f"workgroup/{workgroup}/query/{nq_id}")
                    resources[arn] = nq
    return resources


def scan_opensearch_domains(session: boto3.Session, region: str, _account: str) -> dict:
    es = session.client("opensearch", region_name=region)
    resources = {}
    names = [d["DomainName"] for d in es.list_domain_names().get("DomainNames", [])]
    if names:
        # describe_domains supports max 5 at a time
        for i in range(0, len(names), 5):
            batch = names[i:i + 5]
            resp = es.describe_domains(DomainNames=batch)
            for domain in resp.get("DomainStatusList", []):
                arn = domain.get("ARN", "")
                if arn:
                    resources[arn] = domain
    return resources


def scan_redshift_clusters(session: boto3.Session, region: str, account: str) -> dict:
    rs = session.client("redshift", region_name=region)
    resources = {}
    paginator = rs.get_paginator("describe_clusters")
    for page in paginator.paginate():
        for cluster in page.get("Clusters", []):
            cid = cluster.get("ClusterIdentifier", "")
            if cid:
                arn = build_arn("redshift", region, account, f"cluster:{cid}")
                resources[arn] = cluster
    return resources


# Global services (no region required - called once)
GLOBAL_SCANNERS = {
    "S3 Buckets": scan_s3_buckets,
    "CloudFront Distributions": scan_cloudfront_distributions,
    "Route 53 Hosted Zones": scan_route53_hosted_zones,
}

# Regional services (called per-region)
REGIONAL_SCANNERS = {
    "EC2 Instances": scan_ec2_instances,
    "EC2 VPCs": scan_ec2_vpcs,
    "EC2 Subnets": scan_ec2_subnets,
    "EC2 Route Tables": scan_ec2_route_tables,
    "EC2 Internet Gateways": scan_ec2_internet_gateways,
    "EC2 NAT Gateways": scan_ec2_nat_gateways,
    "EC2 Transit Gateways": scan_ec2_transit_gateways,
    "EC2 Volumes": scan_ec2_volumes,
    "EC2 Network ACLs": scan_ec2_network_acls,
    "EC2 VPN Gateways": scan_ec2_vpn_gateways,
    "EC2 VPC Endpoints": scan_ec2_vpc_endpoints,
    "EC2 Network Interfaces": scan_ec2_network_interfaces,
    "Lambda Functions": scan_lambda_functions,
    "DynamoDB Tables": scan_dynamodb_tables,
    "RDS Instances": scan_rds_instances,
    "RDS Clusters": scan_rds_clusters,
    "RDS Proxies": scan_rds_proxies,
    "ECS Clusters": scan_ecs_clusters,
    "ECS Services": scan_ecs_services,
    "ECS Tasks": scan_ecs_tasks,
    "EKS Clusters": scan_eks_clusters,
    "EFS File Systems": scan_efs_file_systems,
    "ElastiCache Clusters": scan_elasticache_clusters,
    "ElastiCache Replication Groups": scan_elasticache_replication_groups,
    "ELBv2 Load Balancers": scan_elbv2_load_balancers,
    "ELBv2 Target Groups": scan_elbv2_target_groups,
    "ELBv1 Load Balancers": scan_elbv1_load_balancers,
    "SNS Topics": scan_sns_topics,
    "SQS Queues": scan_sqs_queues,
    "CloudTrail Trails": scan_cloudtrail_trails,
    "CloudWatch Alarms": scan_cloudwatch_metric_alarms,
    "CloudWatch Metric Streams": scan_cloudwatch_metric_streams,
    "Auto Scaling Groups": scan_autoscaling_groups,
    "Athena Named Queries": scan_athena_named_queries,
    "OpenSearch Domains": scan_opensearch_domains,
    "Redshift Clusters": scan_redshift_clusters,
}


# ---------------------------------------------------------------------------
# Tags scanner
# ---------------------------------------------------------------------------

def scan_tags(session: boto3.Session) -> tuple[dict, list]:
    """Fetch tags for all supported resource types using Resource Groups Tagging API."""
    client = session.client("resourcegroupstaggingapi")
    tags: dict[str, dict[str, str]] = {}
    errors: list[dict] = []
    service_codes = list(set(TAGGING_RESOURCE_TYPES))

    for code in service_codes:
        try:
            paginator = client.get_paginator("get_resources")
            for page in paginator.paginate(ResourceTypeFilters=[code]):
                for mapping in page.get("ResourceTagMappingList", []):
                    arn = mapping.get("ResourceARN", "")
                    tag_list = mapping.get("Tags", [])
                    if not arn or not tag_list:
                        continue
                    tags[arn] = {}
                    for t in tag_list:
                        k, v = t.get("Key", ""), t.get("Value", "")
                        if k and v:
                            tags[arn][k] = v
        except Exception as e:
            errors.append({"service": f"tags-{code}", "message": str(e)})

    return tags, errors


# ---------------------------------------------------------------------------
# Processing: placement data, resources, containers
# ---------------------------------------------------------------------------

def get_placement_data(arn: str, resource: dict) -> dict | None:
    """Extract placement info from a resource, mirroring getPlacementData.ts."""
    parsed = parse_arn(arn)
    service = parsed["service"]
    res_str = parsed["resource"]
    rtype = get_type_from_arn(service, res_str)
    name = get_name_from_arn(res_str, rtype)
    region = parsed["region"]
    account = parsed["account"]

    # Skip container resources
    if service == "ec2" and rtype in ("vpc", "subnet", "security-group", "availability-zone"):
        return None

    base = {
        "account": account,
        "name": name,
        "region": region,
        "service": service,
        "type": rtype,
        "variant": "",
        "vpc": None,
        "availabilityZones": [],
        "subnets": [],
        "securityGroups": [],
    }

    if service == "athena" and "/query/" in name:
        base["name"] = resource.get("Name", name)
        base["type"] = "named-query"
        return base

    if service == "autoscaling" and rtype == "autoScalingGroup":
        base["name"] = resource.get("AutoScalingGroupName", name)
        base["availabilityZones"] = resource.get("AvailabilityZones", [])
        return base

    if service == "lambda" and rtype == "function":
        vpc_cfg = resource.get("VpcConfig", {})
        base["vpc"] = vpc_cfg.get("VpcId") or None
        base["subnets"] = vpc_cfg.get("SubnetIds", [])
        base["securityGroups"] = vpc_cfg.get("SecurityGroupIds", [])
        return base

    if service == "rds" and rtype == "db":
        sg = resource.get("DBSubnetGroup", {})
        base["vpc"] = sg.get("VpcId") or None
        az = resource.get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        base["subnets"] = [s["SubnetIdentifier"] for s in sg.get("Subnets", []) if s.get("SubnetIdentifier")]
        base["securityGroups"] = [s["VpcSecurityGroupId"] for s in resource.get("VpcSecurityGroups", []) if s.get("VpcSecurityGroupId")]
        return base

    if service == "rds" and rtype == "cluster":
        base["availabilityZones"] = resource.get("AvailabilityZones", [])
        base["securityGroups"] = [s["VpcSecurityGroupId"] for s in resource.get("VpcSecurityGroups", []) if s.get("VpcSecurityGroupId")]
        return base

    if service == "rds" and rtype == "proxy":
        base["vpc"] = resource.get("VpcId") or None
        base["subnets"] = resource.get("VpcSubnetIds", [])
        base["securityGroups"] = resource.get("VpcSecurityGroupIds", [])
        return base

    if service == "ec2" and rtype == "instance":
        base["vpc"] = resource.get("VpcId") or None
        az = (resource.get("Placement") or {}).get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        sid = resource.get("SubnetId")
        base["subnets"] = [sid] if sid else []
        return base

    if service == "ec2" and rtype == "vpc-endpoint":
        base["vpc"] = resource.get("VpcId") or None
        base["subnets"] = resource.get("SubnetIds", [])
        return base

    if service == "ec2" and rtype == "network-interface":
        base["vpc"] = resource.get("VpcId") or None
        az = resource.get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        sid = resource.get("SubnetId")
        base["subnets"] = [sid] if sid else []
        return base

    if service == "ec2" and rtype == "route-table":
        base["vpc"] = resource.get("VpcId") or None
        return base

    if service == "ec2" and rtype == "volume":
        az = resource.get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        return base

    if service == "ec2" and rtype == "internet-gateway":
        attachments = resource.get("Attachments", [])
        base["vpc"] = attachments[0].get("VpcId") if attachments else None
        return base

    if service == "ec2" and rtype == "vpn-gateway":
        az = resource.get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        attachments = resource.get("VpcAttachments", [])
        base["vpc"] = attachments[0].get("VpcId") if attachments else None
        return base

    if service == "ec2" and rtype == "nat-gateway":
        base["vpc"] = resource.get("VpcId") or None
        sid = resource.get("SubnetId")
        base["subnets"] = [sid] if sid else []
        return base

    if service == "ecs" and rtype == "task":
        az = resource.get("availabilityZone")
        base["availabilityZones"] = [az] if az else []
        return base

    if service == "elasticloadbalancing" and rtype == "loadbalancer":
        is_v2 = "LoadBalancerArn" in resource
        if is_v2:
            base["variant"] = "application" if resource.get("Type") == "application" else ""
            base["name"] = resource.get("LoadBalancerName", name)
            base["vpc"] = resource.get("VpcId") or None
            azs = resource.get("AvailabilityZones", [])
            base["availabilityZones"] = [z["ZoneName"] for z in azs if z.get("ZoneName")]
            base["subnets"] = [z["SubnetId"] for z in azs if z.get("SubnetId")]
            base["securityGroups"] = resource.get("SecurityGroups", [])
        else:
            base["name"] = resource.get("LoadBalancerName", name)
            base["vpc"] = resource.get("VPCId") or None
            base["availabilityZones"] = resource.get("AvailabilityZones", [])
            base["subnets"] = resource.get("Subnets", [])
            base["securityGroups"] = resource.get("SecurityGroups", [])
        return base

    if service == "elasticloadbalancing" and rtype == "targetgroup":
        base["vpc"] = resource.get("VpcId") or None
        base["name"] = resource.get("TargetGroupName", name)
        return base

    if service == "elasticfilesystem" and rtype == "file-system":
        az = resource.get("AvailabilityZoneName")
        base["availabilityZones"] = [az] if az else []
        return base

    if service == "redshift" and rtype == "cluster":
        base["vpc"] = resource.get("VpcId") or None
        az = resource.get("AvailabilityZone")
        base["availabilityZones"] = [az] if az else []
        return base

    if service == "ec2" and rtype == "network-acl":
        base["vpc"] = resource.get("VpcId") or None
        base["subnets"] = [a["SubnetId"] for a in resource.get("Associations", []) if a.get("SubnetId")]
        return base

    if service == "route53" and rtype == "hostedzone":
        base["account"] = resource.get("Account", account)
        base["name"] = resource.get("Name", name)
        return base

    if service == "s3":
        base["type"] = "bucket"
        base["name"] = resource.get("Name", name)
        base["account"] = resource.get("Account", account)
        base["region"] = resource.get("Location", region)
        return base

    if service == "es" and rtype == "domain":
        base["name"] = resource.get("DomainName", name)
        vpc_opts = resource.get("VPCOptions", {})
        base["vpc"] = vpc_opts.get("VPCId") or None
        base["availabilityZones"] = vpc_opts.get("AvailabilityZones", [])
        base["subnets"] = vpc_opts.get("SubnetIds", [])
        return base

    return base


def is_subnet_private(subnet: dict) -> bool:
    if not subnet.get("MapPublicIpOnLaunch"):
        return True
    cidr = subnet.get("CidrBlock", "")
    private_ranges = [r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\."]
    if any(re.match(p, cidr) for p in private_ranges):
        return True
    dns_opts = subnet.get("PrivateDnsNameOptionsOnLaunch", {})
    if dns_opts and not dns_opts.get("EnableResourceNameDnsARecord") and not dns_opts.get("EnableResourceNameDnsAAAARecord"):
        return True
    if subnet.get("Ipv6CidrBlockAssociationSet") is not None and len(subnet.get("Ipv6CidrBlockAssociationSet", [])) == 0:
        return True
    return False


def process_data(all_resources: dict, all_tags: dict) -> dict:
    """Build the 'processed' section matching Miro's expected format."""
    # 1. Build placement data
    placement: dict[str, dict] = {}
    for arn, resource in all_resources.items():
        pd = get_placement_data(arn, resource)
        if pd is not None:
            placement[arn] = pd

    # 2. Build processed resources
    processed_resources = {}
    for arn, pd in placement.items():
        unified_type = ":".join(filter(None, [pd["service"], pd["type"], pd["variant"]]))
        processed_resources[arn] = {
            "name": pd["name"],
            "type": unified_type,
            "tags": all_tags.get(arn, {}),
        }

    # 3. Build container scaffolding
    containers = {
        "accounts": {},
        "regions": {},
        "vpcs": {},
        "availabilityZones": {},
        "securityGroups": {},
        "subnets": {},
    }

    for arn, pd in placement.items():
        account = pd["account"]
        region = pd["region"]
        vpc = pd["vpc"]
        azs = pd["availabilityZones"]
        sgs = pd["securityGroups"]
        subnets = pd["subnets"]

        # Account
        if account and account not in containers["accounts"]:
            containers["accounts"][account] = {
                "name": f"Account-{account}",
                "children": {"resources": [], "regions": []},
            }

        # Region
        region_id = f"{account}/{region}" if account and region else None
        if region_id and region_id not in containers["regions"]:
            containers["regions"][region_id] = {
                "name": region,
                "children": {"resources": [], "vpcs": [], "availabilityZones": []},
            }
            if account in containers["accounts"]:
                containers["accounts"][account]["children"]["regions"].append(region_id)

        # VPC
        if vpc and vpc not in containers["vpcs"]:
            containers["vpcs"][vpc] = {
                "name": vpc,
                "children": {"resources": [], "subnets": [], "securityGroups": []},
            }
            if region_id and region_id in containers["regions"]:
                containers["regions"][region_id]["children"]["vpcs"].append(vpc)

        # Availability Zones
        for az in azs:
            az_id = f"{account}/{az}"
            if az_id not in containers["availabilityZones"]:
                containers["availabilityZones"][az_id] = {
                    "name": az,
                    "children": {"resources": [], "subnets": [], "securityGroups": []},
                }
                if region_id and region_id in containers["regions"]:
                    containers["regions"][region_id]["children"]["availabilityZones"].append(az_id)

        # Security Groups
        for sg in sgs:
            if sg not in containers["securityGroups"]:
                containers["securityGroups"][sg] = {
                    "name": sg,
                    "children": {"resources": []},
                }
                if vpc and vpc in containers["vpcs"]:
                    containers["vpcs"][vpc]["children"]["securityGroups"].append(sg)
                for az in azs:
                    az_id = f"{account}/{az}"
                    if az_id in containers["availabilityZones"]:
                        containers["availabilityZones"][az_id]["children"]["securityGroups"].append(sg)

        # Subnets
        for subnet_id in subnets:
            if subnet_id not in containers["subnets"]:
                # Find subnet resource data
                subnet_arn = next((a for a in all_resources if subnet_id in a), None)
                subnet_desc = all_resources.get(subnet_arn, {}) if subnet_arn else {}
                containers["subnets"][subnet_id] = {
                    "name": subnet_id,
                    "children": {"resources": []},
                    "type": "private" if is_subnet_private(subnet_desc) else "public",
                }
                sub_vpc = subnet_desc.get("VpcId")
                if sub_vpc:
                    if sub_vpc not in containers["vpcs"]:
                        containers["vpcs"][sub_vpc] = {
                            "name": sub_vpc,
                            "children": {"resources": [], "subnets": [], "securityGroups": []},
                        }
                        if region_id and region_id in containers["regions"]:
                            containers["regions"][region_id]["children"]["vpcs"].append(sub_vpc)
                    containers["vpcs"][sub_vpc]["children"]["subnets"].append(subnet_id)
                sub_az = subnet_desc.get("AvailabilityZone")
                if sub_az:
                    sub_az_id = f"{account}/{sub_az}"
                    if sub_az_id not in containers["availabilityZones"]:
                        containers["availabilityZones"][sub_az_id] = {
                            "name": sub_az,
                            "children": {"resources": [], "subnets": [], "securityGroups": []},
                        }
                        if region_id and region_id in containers["regions"]:
                            containers["regions"][region_id]["children"]["availabilityZones"].append(sub_az_id)
                    containers["availabilityZones"][sub_az_id]["children"]["subnets"].append(subnet_id)

    # 4. Assign resources to containers (priority: subnet/sg > vpc/az > region > account)
    for arn, pd in placement.items():
        if pd["subnets"] or pd["securityGroups"]:
            for sid in pd["subnets"]:
                if sid in containers["subnets"]:
                    containers["subnets"][sid]["children"]["resources"].append(arn)
            for sg in pd["securityGroups"]:
                if sg in containers["securityGroups"]:
                    containers["securityGroups"][sg]["children"]["resources"].append(arn)
        elif pd["vpc"] or pd["availabilityZones"]:
            if pd["vpc"] and pd["vpc"] in containers["vpcs"]:
                containers["vpcs"][pd["vpc"]]["children"]["resources"].append(arn)
            for az in pd["availabilityZones"]:
                az_id = f"{pd['account']}/{az}"
                if az_id in containers["availabilityZones"]:
                    containers["availabilityZones"][az_id]["children"]["resources"].append(arn)
        elif pd["region"]:
            region_id = f"{pd['account']}/{pd['region']}"
            if region_id in containers["regions"]:
                containers["regions"][region_id]["children"]["resources"].append(arn)
        elif pd["account"]:
            if pd["account"] in containers["accounts"]:
                containers["accounts"][pd["account"]]["children"]["resources"].append(arn)

    # 5. Extract unique tag keys and values
    unique_tags: dict[str, list[str]] = {}
    for tag_map in all_tags.values():
        for k, v in tag_map.items():
            if k not in unique_tags:
                unique_tags[k] = []
            if v and v not in unique_tags[k]:
                unique_tags[k].append(v)

    return {
        "resources": processed_resources,
        "connections": [],
        "containers": containers,
        "tags": unique_tags,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="AWS Cloud Resource Scanner for Miro")
    parser.add_argument("-p", "--profile", help="AWS profile name")
    parser.add_argument("-r", "--regions", nargs="+", default=["us-east-1"],
                        help='AWS regions to scan (use "all" for all regions)')
    parser.add_argument("-o", "--output", default="cloud-data-import.json", help="Output file path")
    parser.add_argument("--raw", action="store_true", help="Include raw resource data in output")
    parser.add_argument("--regional-only", action="store_true", help="Skip global services (S3, CloudFront, Route53)")
    parser.add_argument("--compressed", action="store_true", help="Minify JSON output")
    parser.add_argument("--workers", type=int, default=4, help="Max parallel workers per region")
    args = parser.parse_args()

    regions = ALL_REGIONS if "all" in args.regions else args.regions

    print(f"\n  AWS Cloud Resource Scanner")
    print(f"  Profile: {args.profile or '(default)'}")
    print(f"  Regions: {', '.join(regions)}\n")

    started_at = datetime.now(timezone.utc)

    # Get account ID
    try:
        account_id = get_account_id(args.profile)
        log(f"Account: {account_id}")
    except Exception as e:
        print(f"\n  [ERROR] Failed to resolve AWS credentials: {e}\n", file=sys.stderr)
        sys.exit(1)

    all_resources: dict = {}
    all_errors: list[dict] = []

    # --- Scan global services ---
    if not args.regional_only:
        for name, scanner_fn in GLOBAL_SCANNERS.items():
            log(f"Scanning {name}...")
            try:
                session = get_session(args.profile, regions[0])
                result = scanner_fn(session, regions[0], account_id)
                all_resources.update(result)
                log(f"  found {len(result)} resources")
            except Exception as e:
                all_errors.append({"service": name, "message": str(e)})
                log(f"  error: {e}")

    # --- Scan regional services ---
    for region in regions:
        log(f"\nRegion: {region}")
        region_session = get_session(args.profile, region)

        def _make_runner(sess: boto3.Session, rgn: str, acct: str):
            """Bind loop variables to avoid late-binding closure issues."""
            def _run_scanner(entry: tuple[str, Any]) -> tuple[str, dict, str | None]:
                sname, sfn = entry
                try:
                    result = sfn(sess, rgn, acct)
                    return sname, result, None
                except Exception as e:
                    return sname, {}, str(e)
            return _run_scanner

        runner = _make_runner(region_session, region, account_id)

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(runner, item): item[0] for item in REGIONAL_SCANNERS.items()}
            for future in as_completed(futures):
                sname, result, err = future.result()
                if err:
                    all_errors.append({"service": sname, "region": region, "message": err})
                    log(f"  {sname}: error - {err}")
                elif result:
                    all_resources.update(result)
                    log(f"  {sname}: {len(result)}")

    # --- Scan tags (per-region, since the Tagging API is regional) ---
    log("\nFetching tags...")
    all_tags: dict[str, dict[str, str]] = {}
    for region in regions:
        tag_session = get_session(args.profile, region)
        region_tags, tag_errors = scan_tags(tag_session)
        all_tags.update(region_tags)
        all_errors.extend(tag_errors)
    log(f"  tagged resources: {len(all_tags)}")

    finished_at = datetime.now(timezone.utc)
    duration = (finished_at - started_at).total_seconds()

    # --- Build output ---
    output: dict[str, Any] = {
        "provider": "aws",
        "docVersion": "0.1.5",
        "resources": all_resources if args.raw else {},
        "tags": all_tags if args.raw else {},
        "processed": process_data(all_resources, all_tags),
        "errors": all_errors,
        "metadata": {
            "account": account_id,
            "regions": regions,
            "startedAt": started_at.isoformat(),
            "finishedAt": finished_at.isoformat(),
        },
    }

    # --- Write output ---
    indent = None if args.compressed else 2
    with open(args.output, "w") as f:
        json.dump(output, f, indent=indent, default=json_serial)

    total = len(all_resources)
    print(f"\n  Done! Scanned {total} resources in {duration:.1f}s")
    print(f"  Output: {args.output}\n")


if __name__ == "__main__":
    main()
