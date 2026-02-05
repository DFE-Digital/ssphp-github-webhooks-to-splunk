# Send GitHub Webhooks events to Splunk SIEM

Sending Webhooks events directly to the Splunk HEC endpoint results in missing metadata, specifically the event type.

This proxy server adds all headers including the event type into the JSON body and forwards to Splunk HEC.

It runs as an Azure Function app which is built using Terraform when a PR is merged into main.


