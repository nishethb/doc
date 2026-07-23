import groovy.json.JsonOutput
import java.util.UUID
import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

// ── GENERATE xsmid ────────────────────────────────────────────────────────────
def xsmid = UUID.randomUUID().toString()

logger.info('[Authenticate] HRT authenticate called')
logger.info('[Authenticate] xsmid generated: ' + xsmid)

// ── BUILD RESPONSE — Exact Client Spec Format ─────────────────────────────────
// Request:  {} empty body
// Response:
//   headers = OBJECT (not array) with session_id and type
//   data.data.json_data has action, rsaTransactionId, xsmid
//   data.token = JWT (empty at this stage — JWT comes after step-up)
//   data.state = "completed"
//   data.application_data = ""
//   data.assertions_complete = true
//   error_code = 0

def r = new Response(Status.OK)
r.headers.put('Content-Type', 'application/json')
r.entity.string = JsonOutput.toJson([
    error_message: '',
    headers      : [
        session_id: xsmid,
        type      : 'session_id'
    ],
    data         : [
        data             : [
            json_data: [
                action           : 'CHALLENGE',
                rsaTransactionId : 'N/A',
                xsmid            : xsmid
            ]
        ],
        state              : 'completed',
        application_data   : '',
        assertions_complete: true,
        token              : ''
    ],
    error_code   : 0
])

logger.info('[Authenticate] Response sent — xsmid: ' + xsmid)
return r