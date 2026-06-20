---
session: ses_1225
updated: 2026-06-19T04:57:39.935Z
---

<｜｜DSML｜｜tool_calls>
<｜｜DSML｜｜invoke name="bash">
<｜｜DSML｜｜parameter name="command" string="true">$env:PYTHONIOENCODING='utf-8'; python -c "
# Check if docx file is locked
import os
path = r'D:\testcase_web\Bao_Cao_Thuc_Tap_WebSec_Test_Behavior_Tree.docx'
try:
    f = open(path, 'ab')
    f.close()
    print('File is NOT locked')
except PermissionError as e:
    print(f'File IS locked: {e}')
except Exception as e:
    print(f'Other error: {e}')
" 2>&1</｜｜DSML｜｜parameter>
<｜｜DSML｜｜parameter name="description" string="true">Check if DOCX file is locked</｜｜DSML｜｜parameter>
<｜｜DSML｜｜parameter name="timeout" string="false">5000</｜｜DSML｜｜parameter>
</｜｜DSML｜｜invoke>
</｜｜DSML｜｜tool_calls>
