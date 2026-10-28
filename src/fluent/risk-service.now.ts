
import '@servicenow/sdk/global'
import { ScriptInclude } from '@servicenow/sdk/core'

ScriptInclude({
    $id: Now.ID['uia-risk-service'],
    name: 'UIARiskService',
    apiName: 'x_2280382_uiasyste.UIARiskService',
    active: true,
    script: Now.include('../server/risk-service.server.js')
})
