## Workbooks
Workbooks provided here are samples of what is possible to address specific scenarios.

To use any of the workbooks found here, create a new workbook in Azure Monitor, and copy the code from this sample into the code area for the workbook, replacing the sample code in this workbook:

![workbook code](workbook-code.png)

## Daily checks automation

`scripts/daily_checks/` is a standalone Python CLI that pulls team workload
from ServiceNow and security posture from Microsoft Sentinel/Defender and
Armis into a single morning report. See
[scripts/daily_checks/README.md](scripts/daily_checks/README.md) for setup.