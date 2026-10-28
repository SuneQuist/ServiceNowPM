
import '@servicenow/sdk/global'
import { UiPage } from '@servicenow/sdk/core'

UiPage({
    $id: Now.ID['uia-patch-plan-page'],
    endpoint: 'x_2280382_uiasyste_patch_plan.do',
    description: 'Patch and Mitigation assessment dialog',
    category: 'general',
    direct: false,
    html: Now.include('./patch-plan.jelly.xml')
})
