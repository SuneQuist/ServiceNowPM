
import '@servicenow/sdk/global'
import { UiAction } from '@servicenow/sdk/core'

UiAction({
    $id: Now.ID['assess-incident'],
    name: 'Assess Patch Risk',
    actionName: 'uia_assess_patch_risk',
    table: 'incident',
    active: true,
    showUpdate: true,
    form: { showButton: true },
    script: `
        var incidentId = current.getUniqueValue();

        var pageUrl =
            'x_2280382_uiasyste_patch_plan.do' +
            '?sysparm_incident_id=' + incidentId;

        action.setRedirectURL(pageUrl);
    `
})