import json
import boto3
import botocore
from botocore.exceptions import ClientError

AWS_REGION = "us-east-1"

def describeServiceItems( client , describe_function, key_items, parameters={}, next_step=""):
	try:
		parameters_to_add = ""
		for key, val in parameters.items():
		    if type(val) is str:
		        parameters_to_add += key+'="'+val+'", '
		    if type(val) is int:
		        parameters_to_add += key+'='+str(val)+', '
		if (next_step!=""):
			if describe_function=="list_resource_record_sets":
				strfunction = "client."+describe_function+"(StartRecordName='"+next_step+"', "+parameters_to_add+")"
			else:
				strfunction = "client."+describe_function+"(NextToken='"+next_step+"', "+parameters_to_add+")"
			response = eval(strfunction)
		else:
			strfunction = "client."+describe_function+"("+parameters_to_add+")"
			response = eval(strfunction)
		print(response)
		if response['ResponseMetadata']['HTTPStatusCode']!=200:
			return False
		else:
		    keys = key_items.split(",")
		    if len(keys)>1:
		        listItems = {}
		        for key in keys:
		            listItems[key] = response[key]
		            
        		if 'NextToken' in response:
        			resp2 = describeServiceItems(client, describe_function, key_items, parameters, response['NextToken'])
        			for key in keys:
        			    listItems[key] += resp2[key]
        		if 'NextRecordName' in response:
        			resp2 += describeServiceItems(client, describe_function, key_items, parameters, response['NextRecordName'])
        			for key in keys:
        			    listItems[key] += resp2[key]
		    else:
		        listItems = []
		        listItems = response[key_items]
        		if 'NextToken' in response:
        			listItems += describeServiceItems(client, describe_function, key_items, parameters, response['NextToken'])
        		if 'NextRecordName' in response:
        			listItems += describeServiceItems(client, describe_function, key_items, parameters, response['NextRecordName'])
		    return listItems
	except botocore.exceptions.EndpointConnectionError as e:
		print(e)
		return False
	except ClientError as e:
		print(e)
		return False

def list_detectors(event, context):
    L4M = boto3.client( "lookoutmetrics", region_name=AWS_REGION )
    response = describeServiceItems(L4M, "list_anomaly_detectors", "AnomalyDetectorSummaryList" )
    detectors = []
    for item in response:
        detectors.append({
            "AnomalyDetectorArn": item["AnomalyDetectorArn"],
            "AnomalyDetectorName": item["AnomalyDetectorName"],
            "CreationTime": item["CreationTime"].strftime("%m/%d/%Y, %H:%M:%S"),
            "LastModificationTime": item["LastModificationTime"].strftime("%m/%d/%Y, %H:%M:%S"),
            "Status": item["Status"]
        })
    return {
        "statusCode": 200,
        "body": json.dumps(detectors),
    }


def list_anomaly_group_summaries(event, context):
    path_parameters = event['pathParameters']
    print(path_parameters)
    L4M = boto3.client( "lookoutmetrics", region_name=AWS_REGION )
    response = describeServiceItems(L4M, "list_anomaly_group_summaries", "AnomalyGroupSummaryList", 
        { "AnomalyDetectorArn" : path_parameters["AnomalyDetectorArn"], "SensitivityThreshold" : 50, "MaxResults" : 100 } )
    '''
    summaries = []
    for item in response:
        summaries.append({
            "AnomalyGroupId": item["AnomalyGroupId"],
            "AnomalyGroupScore": item["AnomalyGroupScore"],
            "StartTime": item["StartTime"],
            "EndTime": item["EndTime"],
            "PrimaryMetricName": item["PrimaryMetricName"]
        })
    '''
    return {
        "statusCode": 200,
        "body": json.dumps(response),
    }
    
    
def list_anomaly_group_time_series(event, context):
    path_parameters = event['pathParameters']
    print(path_parameters)
    L4M = boto3.client( "lookoutmetrics", region_name=AWS_REGION )
    response = describeServiceItems(L4M, "list_anomaly_group_time_series", "TimeSeriesList,TimestampList", 
        {
            "AnomalyDetectorArn" : path_parameters["AnomalyDetectorArn"],
            "AnomalyGroupId" : path_parameters["AnomalyGroupId"],
            "MetricName" : path_parameters["MetricName"],
            "MaxResults" : 10,
        })
    print(response)
    '''
    for item in response:
        summaries.append({
            "AnomalyGroupId": item["AnomalyGroupId"],
            "AnomalyGroupScore": item["AnomalyGroupScore"],
            "StartTime": item["StartTime"],
            "EndTime": item["EndTime"],
            "PrimaryMetricName": item["PrimaryMetricName"]
        })
    '''
    return {
        "statusCode": 200,
        "body": json.dumps(response),
    }
