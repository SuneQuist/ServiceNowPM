
var UIARiskService = Class.create();

UIARiskService.prototype = {
    initialize: function () {},

    // SSVC v2.0 (2021), Figure 2, p. 35.
    // Human Impact order: Very High, High, Medium, Low.
    // I=Immediate, O=Out-of-Cycle, S=Scheduled, D=Defer.
    tree: {
        active: {
            open: {
                super_effective: 'IIOO',
                efficient: 'IIOS',
                laborious: 'IOSS'
            },
            controlled: {
                super_effective: 'OOOS',
                efficient: 'OOSS',
                laborious: 'OOSS'
            },
            small: {
                super_effective: 'OOSS',
                efficient: 'OOSS',
                laborious: 'OOSS'
            }
        },
        poc: {
            open: {
                super_effective: 'OOSS',
                efficient: 'OSSS',
                laborious: 'OSSD'
            },
            controlled: {
                super_effective: 'OSSS',
                efficient: 'SSSS',
                laborious: 'SSSD'
            },
            small: {
                super_effective: 'SSSS',
                efficient: 'SSSD',
                laborious: 'SSSD'
            }
        },
        none: {
            open: {
                super_effective: 'OSSS',
                efficient: 'SSSS',
                laborious: 'SSSD'
            },
            controlled: {
                super_effective: 'SSSS',
                efficient: 'SSSD',
                laborious: 'SSSD'
            },
            small: {
                super_effective: 'SSSD',
                efficient: 'SSSD',
                laborious: 'SSDD'
            }
        }
    },

    assess: function (incidentId, supplied) {
        if (!/^[0-9a-f]{32}$/i.test(String(incidentId || ''))) {
            return {
                success: false,
                message: 'Invalid Incident identifier.'
            };
        }

        var incident = new GlideRecordSecure('incident');

        if (!incident.get(incidentId)) {
            return {
                success: false,
                message: 'Incident unavailable or access denied.'
            };
        }

        var c = this.normalize(supplied || {});

        c.utility = this.utility(
            c.automatable,
            c.valueDensity
        );

        c.humanImpact = this.humanImpact(
            c.safety,
            c.mission
        );

        var decision = this.decide(c);

        var contact = {
            name: '',
            phone: '',
            group: incident.getDisplayValue('assignment_group') || ''
        };

        var userId = incident.getValue('assigned_to');

        if (userId) {
            var person = new GlideRecordSecure('sys_user');

            if (person.get(userId)) {
                contact.name =
                    person.getDisplayValue('name') || '';

                if (
                    person.isValidField('phone') &&
                    person.getElement('phone').canRead()
                ) {
                    contact.phone =
                        person.getValue('phone') || '';
                }
            }
        }

        var missing = [];

        var required = [
            ['applicability', 'Affected version / applicability'],
            ['exploitation', 'Exploitation evidence'],
            ['exposure', 'System exposure'],
            ['automatable', 'Exploit automatability'],
            ['valueDensity', 'Value density'],
            ['safety', 'Situated safety impact'],
            ['mission', 'Mission impact'],
            ['patch', 'Patch availability']
        ];

        for (var i = 0; i < required.length; i++) {
            if (c[required[i][0]] === 'unknown') {
                missing.push(required[i][1]);
            }
        }

        var rationale = [
            'SSVC v2.0 Deployer priority is separate from Incident Impact, Urgency and Priority.',

            'Tree path: Exploitation = ' + c.exploitation +
            '; Exposure = ' + c.exposure +
            '; Utility = ' + c.utility +
            '; Human Impact = ' + c.humanImpact + '.',

            'Utility derives from Automatable + Value Density. Human Impact derives from Safety + Mission Impact.'
        ];

        if (decision.incomplete) {
            rationale.push(
                'Incomplete inputs: possible tree outcomes are ' +
                decision.possible.join(', ') + '.'
            );
        } else if (decision.code !== 'not_applicable') {
            rationale.push(
                'The exact Figure 2 tree leaf is ' +
                decision.priority + '.'
            );
        }

        if (parseInt(incident.getValue('priority'), 10) <= 2) {
            rationale.push(
                'Incident Priority 1/2 requires separate operational coordination; it does not alter the SSVC tree.'
            );
        }

        return {
            success: true,
            rulesVersion: 'SSVC-2021-v2.0-Figure2',
            incidentId: incident.getUniqueValue(),
            incidentNumber: incident.getValue('number'),
            impact: incident.getValue('impact'),
            urgency: incident.getValue('urgency'),
            priority: incident.getValue('priority'),
            configurationItem:
                incident.getDisplayValue('cmdb_ci') || 'Not specified',
            contact: contact,
            context: c,
            decision: decision,
            rationale: rationale,
            missingInformation: missing,
            mitigationGuide: this.mitigation(c, decision),
            patchingGuide: this.patching(c, decision)
        };
    },

    pick: function (v, values) {
        v = String(v || 'unknown');

        for (var i = 0; i < values.length; i++) {
            if (v === values[i]) {
                return v;
            }
        }

        return 'unknown';
    },

    normalize: function (raw) {
        var cve = String(raw.cve || '')
            .toUpperCase()
            .replace(/^\s+|\s+$/g, '');

        if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(cve)) {
            cve = '';
        }

        return {
            cve: cve,

            applicability: this.pick(
                raw.applicability,
                ['unknown', 'affected', 'not_affected']
            ),

            exploitation: this.pick(
                raw.exploitation,
                ['unknown', 'none', 'poc', 'active']
            ),

            exposure: this.pick(
                raw.exposure,
                ['unknown', 'small', 'controlled', 'open']
            ),

            automatable: this.pick(
                raw.automatable,
                ['unknown', 'yes', 'no']
            ),

            valueDensity: this.pick(
                raw.valueDensity,
                ['unknown', 'diffuse', 'concentrated']
            ),

            safety: this.pick(
                raw.safety,
                [
                    'unknown',
                    'minor',
                    'major',
                    'hazardous',
                    'catastrophic'
                ]
            ),

            mission: this.pick(
                raw.mission,
                [
                    'unknown',
                    'limited',
                    'mef_failure',
                    'mission_failure'
                ]
            ),

            patch: this.pick(
                raw.patch,
                [
                    'unknown',
                    'available',
                    'unavailable',
                    'unsupported'
                ]
            )
        };
    },

    // SSVC 2021, Tables 7 and 8.
    utility: function (automatable, density) {
        if (
            automatable === 'unknown' ||
            density === 'unknown'
        ) {
            return 'unknown';
        }

        if (
            automatable === 'yes' &&
            density === 'concentrated'
        ) {
            return 'super_effective';
        }

        if (
            automatable === 'no' &&
            density === 'diffuse'
        ) {
            return 'laborious';
        }

        return 'efficient';
    },

    // SSVC 2021, Table 12.
    humanImpact: function (safety, mission) {
        if (
            safety === 'unknown' ||
            mission === 'unknown'
        ) {
            return 'unknown';
        }

        if (
            safety === 'catastrophic' ||
            mission === 'mission_failure'
        ) {
            return 'very_high';
        }

        if (safety === 'hazardous') {
            return 'high';
        }

        if (safety === 'major') {
            return mission === 'mef_failure'
                ? 'high'
                : 'medium';
        }

        return mission === 'mef_failure'
            ? 'medium'
            : 'low';
    },

    leaf: function (
        exploitation,
        exposure,
        utility,
        humanImpact
    ) {
        var index = {
            very_high: 0,
            high: 1,
            medium: 2,
            low: 3
        }[humanImpact];

        var letter = this.tree[exploitation]
            [exposure]
            [utility]
            .charAt(index);

        return {
            I: 'Immediate',
            O: 'Out-of-Cycle',
            S: 'Scheduled',
            D: 'Defer'
        }[letter];
    },

    decide: function (c) {
        if (c.applicability === 'not_affected') {
            return {
                code: 'not_applicable',
                priority: 'Not applicable',
                title: 'Verify and document non-applicability',
                summary:
                    'Confirm product and version evidence before closing the finding.',
                incomplete: true,
                possible: []
            };
        }

        var dimensions = [
            [c.exploitation, ['none', 'poc', 'active']],
            [c.exposure, ['small', 'controlled', 'open']],
            [
                c.utility,
                ['laborious', 'efficient', 'super_effective']
            ],
            [
                c.humanImpact,
                ['low', 'medium', 'high', 'very_high']
            ]
        ];

        var options = [];

        for (var i = 0; i < dimensions.length; i++) {
            options.push(
                dimensions[i][0] === 'unknown'
                    ? dimensions[i][1]
                    : [dimensions[i][0]]
            );
        }

        // Evaluate every possible tree branch when evidence
        // is incomplete. Never assume unknown means low risk.
        var found = {};

        for (var e = 0; e < options[0].length; e++) {
            for (var x = 0; x < options[1].length; x++) {
                for (var u = 0; u < options[2].length; u++) {
                    for (var h = 0; h < options[3].length; h++) {
                        var result = this.leaf(
                            options[0][e],
                            options[1][x],
                            options[2][u],
                            options[3][h]
                        );

                        found[result] = true;
                    }
                }
            }
        }

        var order = [
            'Defer',
            'Scheduled',
            'Out-of-Cycle',
            'Immediate'
        ];

        var possible = [];

        for (var j = 0; j < order.length; j++) {
            if (found[order[j]]) {
                possible.push(order[j]);
            }
        }

        var unknown = c.applicability !== 'affected';

        for (var k = 0; k < dimensions.length; k++) {
            if (dimensions[k][0] === 'unknown') {
                unknown = true;
            }
        }

        // Only an ambiguous tree result is blocked by missing inputs.
        // If all branches agree, return the determinate SSVC priority.
        if (c.applicability !== 'affected' || possible.length !== 1) {
            return {
                code: 'incomplete',
                priority: 'Assessment incomplete',
                title: 'Confirm the missing SSVC evidence',
                summary:
                    'Possible response priorities: ' +
                    possible.join(' / ') +
                    '. Do not interpret unknown inputs as low risk.',
                incomplete: true,
                possible: possible
            };
        }

        var priority = possible[0];

        var descriptions = {
            'Defer': [
                'defer',
                'Document and monitor',
                'No immediate action is indicated by this tree leaf; reassess if evidence changes.'
            ],

            'Scheduled': [
                'scheduled',
                'Plan remediation in normal maintenance',
                'Coordinate an authorized fix or mitigation during routine maintenance.'
            ],

            'Out-of-Cycle': [
                'out_of_cycle',
                'Accelerate mitigation or patching',
                'Coordinate action at the next available opportunity outside routine maintenance.'
            ],

            'Immediate': [
                'immediate',
                'Coordinate immediate security response',
                'Engage Information Security and the service owner immediately; assess containment and safe remediation.'
            ]
        };

        var d = descriptions[priority];

        return {
            code: d[0],
            priority: priority,
            title: d[1],
            summary: d[2],
            incomplete: false,
            evidenceComplete: !unknown,
            possible: possible
        };
    },

    step: function (title, action, role, explanation) {
        return {
            title: title,
            action: action,
            role: role,
            explanation: explanation
        };
    },

    // Action plans use the SSVC response to determine the operational
    // workflow. They never infer a vendor-specific patch or deploy changes.
    // Incomplete evidence must not be treated as a Defer decision.
    responseMode: function (d) {
        if (d.code === 'not_applicable') {
            return 'not_applicable';
        }
        if (d.incomplete || d.code === 'incomplete') {
            return 'incomplete';
        }
        return d.code;
    },

    // No automatic CMDB relationship or organizational impact discovery.
    // The incident's CI, when present, is only an identifier to verify.
    mitigation: function (c, d) {
        var mode = this.responseMode(d);
        var steps = [];
        var exposureAction = c.exposure === 'open'
            ? 'Review approved restrictions for broadly reachable access paths.'
            : 'Review vendor workarounds and applicable access restrictions.';

        if (mode === 'not_applicable') {
            return [
                this.step(
                    'Validate non-applicability',
                    'Confirm the installed product and version are outside the affected range.',
                    'System owner / Information Security',
                    'Keep the vendor advisory and local version evidence with the assessment.'
                ),
                this.step(
                    'Record disposition',
                    'Document why mitigation is unnecessary for this installation.',
                    'Information Security / Incident owner',
                    'Reassess if the affected version, deployment or advisory changes.'
                )
            ];
        }

        if (mode === 'incomplete') {
            steps.push(this.step(
                'TRIAGE - resolve missing SSVC evidence',
                'Verify applicability, exploitation, exposure, utility and human impact before choosing a response deadline.',
                'Information Security / System owner',
                'Possible SSVC outcomes: ' + (d.possible || []).join(', ') + '. Unknown does not mean low risk.'
            ));
            if ((d.possible || []).indexOf('Immediate') !== -1) {
                steps.push(this.step(
                    'Check whether urgent containment is needed',
                    'Escalate promptly for security review because Immediate remains a possible outcome.',
                    'Information Security / Incident commander',
                    'Assess verified exploitation and reachability; apply interim controls only when justified and authorized.'
                ));
            }
            steps.push(this.step(
                'Evaluate reversible interim protections',
                exposureAction + ' Do not assume the system is exploitable without verification.',
                'System owner / Information Security',
                'Balance risk reduction against service continuity and obtain normal change approval.'
            ));
            steps.push(this.step(
                'Recalculate and select a response',
                'Update the missing fields, recalculate SSVC and replace this provisional plan.',
                'Incident owner / Information Security',
                'Record evidence sources and the accountable owner for each unresolved input.'
            ));
            return steps;
        }

        if (mode === 'immediate') {
            steps.push(this.step(
                'IMMEDIATE - activate coordinated security response',
                'Contact Information Security and the service owner now; establish incident coordination and assign containment ownership.',
                'Information Security / Incident commander',
                'The SSVC decision is Immediate. Incident priority is a separate operational classification.'
            ));
            steps.push(this.step(
                'Assess and contain verified attack paths',
                'Urgently evaluate safe, authorized isolation, access restrictions or vendor workarounds for the affected deployment.',
                'SOC / System owner / IT operations',
                'Prioritize effective, reversible controls while protecting essential service continuity.'
            ));
            steps.push(this.step(
                'Coordinate emergency change and recovery readiness',
                'Obtain required emergency approvals, prepare backups or rollback and communicate expected disruption.',
                'Change manager / Service owner',
                'Do not implement a change without an authorized execution and recovery plan.'
            ));
        } else if (mode === 'out_of_cycle') {
            steps.push(this.step(
                'OUT-OF-CYCLE - assign accelerated remediation',
                'Coordinate Information Security and the system owner; schedule action outside routine maintenance.',
                'Information Security / Service owner',
                'Agree an accountable owner and a justified remediation window under local policy.'
            ));
            steps.push(this.step(
                'Reduce exposure before permanent remediation',
                exposureAction + ' Prioritize controls that interrupt the verified attack path.',
                'IT operations / Information Security',
                'Validate effectiveness and document residual risk.'
            ));
            steps.push(this.step(
                'Approve an expedited change',
                'Arrange testing, authorization, rollback and communications for an accelerated change.',
                'Change manager / System owner',
                'An out-of-cycle response is expedited, but not an automatic emergency deployment.'
            ));
        } else if (mode === 'scheduled') {
            steps.push(this.step(
                'SCHEDULED - place mitigation in maintenance planning',
                'Assign the work to a planned maintenance window with an owner and review date.',
                'Service owner / IT operations',
                'Track the SSVC decision and the supporting evidence in the normal change process.'
            ));
            steps.push(this.step(
                'Evaluate proportionate interim safeguards',
                exposureAction + ' Implement only if justified by the actual deployment risk.',
                'Information Security / System owner',
                'Prefer controls that can be tested and reversed safely.'
            ));
            steps.push(this.step(
                'Prepare the approved maintenance change',
                'Confirm testing, operational communications and rollback before the planned window.',
                'Change manager / IT operations',
                'Escalate if exploitation evidence, exposure or impact increases.'
            ));
        } else { // Defer
            steps.push(this.step(
                'DEFER - document the response decision',
                'Record the completed SSVC path, supporting evidence, accountable owner and review trigger.',
                'Information Security / Service owner',
                'Defer is an SSVC response, not proof that the vulnerability is harmless.'
            ));
            steps.push(this.step(
                'Monitor for changes that invalidate deferral',
                'Watch for new exploitation evidence, deployment exposure changes or updated vendor guidance.',
                'Information Security / Incident owner',
                'Recalculate SSVC if relevant evidence changes; follow local risk governance.'
            ));
            steps.push(this.step(
                'Apply optional low-disruption safeguards if warranted',
                'Consider proportionate, authorized controls without creating unnecessary service risk.',
                'System owner / IT operations',
                'No immediate containment is prescribed solely by this Defer leaf.'
            ));
        }

        steps.push(this.step(
            mode === 'defer' ? 'Review and reassess' : 'Verify controls and reassess',
            mode === 'defer'
                ? 'Revisit the decision at the documented trigger or review point.'
                : 'Test service functionality and mitigation effectiveness; record remaining exposure.',
            'IT operations / Information Security',
            'Retain verification evidence and recalculate SSVC when any decision input changes.'
        ));
        return steps;
    },

    patching: function (c, d) {
        var mode = this.responseMode(d);
        var steps = [];

        if (mode === 'not_applicable') {
            return [
                this.step(
                    'Confirm patch is not applicable',
                    'Verify the installed version is not affected using the vendor advisory.',
                    'Application owner / Information Security',
                    'Retain the version check and advisory as evidence.'
                ),
                this.step(
                    'Document and monitor',
                    'Record the non-applicable disposition; reassess after material changes.',
                    'Incident owner',
                    'Do not install a vulnerability-specific patch solely on the basis of an unrelated CVE.'
                )
            ];
        }

        if (mode === 'incomplete') {
            steps.push(this.step(
                'TRIAGE - determine patching priority',
                'Resolve the missing SSVC inputs before committing to a routine or expedited deployment window.',
                'Information Security / Application owner',
                'Possible responses: ' + (d.possible || []).join(', ') + '. Do not treat unknown as Defer.'
            ));
        } else if (mode === 'immediate') {
            steps.push(this.step(
                'IMMEDIATE - coordinate urgent patch response',
                'Engage Information Security, the application owner and the change manager now.',
                'Information Security / Incident commander',
                'Evaluate an authorized emergency change and safe interim mitigation.'
            ));
        } else if (mode === 'out_of_cycle') {
            steps.push(this.step(
                'OUT-OF-CYCLE - expedite patch scheduling',
                'Arrange a prioritized deployment outside routine maintenance with an agreed owner.',
                'Application owner / Change manager',
                'Use expedited authorization and retain testing and recovery safeguards.'
            ));
        } else if (mode === 'scheduled') {
            steps.push(this.step(
                'SCHEDULED - reserve a maintenance window',
                'Plan patching in the normal authorized maintenance cycle.',
                'Application owner / Change manager',
                'Assign an owner and reassess if threat or exposure changes.'
            ));
        } else { // Defer
            steps.push(this.step(
                'DEFER - record patching disposition',
                'Document why the current SSVC leaf does not require immediate patching and define reassessment triggers.',
                'Information Security / Service owner',
                'Follow local risk governance; defer is not a permanent exemption from patch management.'
            ));
        }

        if (c.patch === 'unavailable') {
            steps.push(this.step(
                'NO PATCH - verify vendor workaround',
                'Confirm no supported fix is currently available; use the mitigation plan and monitor the vendor advisory.',
                'Application owner / Information Security',
                'Do not claim remediation is complete while the vulnerability remains present.'
            ));
        } else if (c.patch === 'unsupported') {
            steps.push(this.step(
                'UNSUPPORTED - plan upgrade or replacement',
                'Confirm end of support and identify a supported version or replacement; use interim mitigations as needed.',
                'Service owner / Architecture / Information Security',
                'Record residual risk, a migration owner and the required approvals.'
            ));
        } else if (c.patch === 'unknown') {
            steps.push(this.step(
                'VERIFY PATCH STATUS - consult the vendor',
                'Check the official advisory for affected versions, supported fixes and prerequisites.',
                'Application owner / Information Security',
                'Do not assume a patch exists or is appropriate for this installation.'
            ));
        } else {
            steps.push(this.step(
                'Confirm the applicable vendor patch',
                'Match the supported fix and prerequisites to the installed product and version.',
                'Application owner / Information Security',
                'Check authenticity, compatibility and vendor instructions before deployment.'
            ));
        }

        if (mode !== 'defer') {
            steps.push(this.step(
                'Test, authorize and prepare rollback',
                mode === 'immediate'
                    ? 'Perform risk-proportionate expedited validation, obtain emergency authorization and prepare recovery.'
                    : 'Test compatibility, plan service continuity and obtain the appropriate change approval.',
                'Application team / Change manager / Service owner',
                'Document backups, rollback, deployment ownership and communication; never deploy automatically.'
            ));
        }

        if (c.patch === 'available' && mode !== 'defer') {
            steps.push(this.step(
                mode === 'immediate' ? 'Execute authorized emergency patch' :
                    mode === 'out_of_cycle' ? 'Execute authorized expedited patch' :
                    mode === 'scheduled' ? 'Deploy in approved maintenance window' :
                    'Deploy after SSVC triage and authorization',
                mode === 'incomplete'
                    ? 'Do not select the deployment window until evidence is reviewed; deploy only after approval.'
                    : 'Deploy the validated patch in the authorized window with recovery safeguards.',
                'IT operations / Change manager',
                'Use normal operational controls, monitoring and rollback criteria.'
            ));
        }

        steps.push(this.step(
            mode === 'defer' ? 'Reassess patching need' : 'Verify remediation and record evidence',
            mode === 'defer'
                ? 'Monitor new advisories and exploitation evidence; revisit the deferral when conditions change.'
                : c.patch === 'available'
                    ? 'Verify the installed version, confirm vulnerability resolution and check service health.'
                    : 'Verify interim protections and revisit the patch or replacement plan when circumstances change.',
            'System owner / Information Security',
            'Document test results, residual risk and reassessment triggers.'
        ));
        return steps;
    },

    type: 'UIARiskService'
};
