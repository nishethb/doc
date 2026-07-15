import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.security.MessageDigest
import java.util.Base64
import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

def AIC_BASE = 'https://openam-kpmg-enablement.forgeblocks.com'
def REALM    = '/am/oauth2/realms/root/realms/alpha'

// ── PARSE REQUEST ─────────────────────────────────────────────────────────────
def jwt   = ''
def xsmid = ''
try {
    def body = new JsonSlurper().parseText(request.entity.string ?: '{}')
    jwt      = body?.jwt   ?: ''
    xsmid    = body?.xsmid ?: ''
} catch(e) {
    logger.error('[Validate] Parse error: ' + e)
    def r = new Response(Status.BAD_REQUEST)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([valid:false, error:'INVALID_JSON'])
    return r
}

logger.info('[Validate] xsmid: '      + xsmid)
logger.info('[Validate] jwt length: ' + jwt.length())

if (!jwt || !xsmid) {
    def r = new Response(Status.BAD_REQUEST)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([valid:false, error:'MISSING_PARAMS'])
    return r
}

// ── CALL idtokeninfo — NO CLIENT AUTH (RS256 — auth not required) ─────────────
// Prerequisite: AIC → OAuth2 Provider → Advanced OpenID Connect
//               → "Idtokeninfo Endpoint Requires Client Authentication" = OFF
logger.info('[Validate] Calling AIC /idtokeninfo (no client auth required for RS256)...')

def idInfoReq = new Request()
idInfoReq.method = 'POST'
idInfoReq.uri    = new URI("${AIC_BASE}${REALM}/idtokeninfo")
idInfoReq.headers.put('Content-Type', 'application/x-www-form-urlencoded')
idInfoReq.entity.string =
    'client_id='      + URLEncoder.encode('ig-poc-client', 'UTF-8') +
    '&client_secret=' + URLEncoder.encode('Password@123',  'UTF-8') +
    '&id_token='      + URLEncoder.encode(jwt.trim(),      'UTF-8')

return http.send(idInfoReq).then(
    { resp ->
        def raw        = resp.entity.string
        def statusCode = resp.status.code as int

        logger.info('[Validate] idtokeninfo status:   ' + statusCode)
        logger.info('[Validate] idtokeninfo response: ' + raw)

        if (statusCode != 200) {
            logger.error('[Validate] idtokeninfo rejected: ' + statusCode)
            def r = new Response(Status.UNAUTHORIZED)
            r.headers.put('Content-Type', 'application/json')
            r.entity.string = JsonOutput.toJson([
                valid  : false,
                error  : 'TOKEN_INVALID',
                message: 'AIC rejected id_token — status: ' + statusCode,
                detail : raw
            ])
            return r
        }

        // AIC validated token ✅ — parse returned claims
        def claims   = new JsonSlurper().parseText(raw)
        def jwtXsmid = claims?.xsmid  ? claims.xsmid.toString()  : ''
        def sHash    = claims?.s_hash ? claims.s_hash.toString() : ''
        def userId   = claims?.sub    ? claims.sub.toString()    : 'unknown'
        def acr      = claims?.acr    ? claims.acr.toString()    : ''
        def exp      = claims?.exp    ?: 0

        logger.info('[Validate] AIC validated id_token ✅')
        logger.info('[Validate] xsmid in JWT:     ' + (jwtXsmid ?: 'NOT PRESENT'))
        logger.info('[Validate] xsmid in request: ' + xsmid)
        logger.info('[Validate] acr:              ' + acr)

        // Method 1: xsmid claim
        if (jwtXsmid && jwtXsmid.trim() == xsmid.trim()) {
            logger.info('[Validate] ✅ MATCH via JWT claim')
            def r = new Response(Status.OK)
            r.headers.put('Content-Type', 'application/json')
            r.entity.string = JsonOutput.toJson([
                valid      : true,
                decision   : 'APPROVED',
                xsmid      : xsmid,
                userId     : userId,
                acr        : acr,
                expiresAt  : exp,
                matchMethod: 'JWT_CLAIM',
                message    : 'HRT transaction validated successfully'
            ])
            return r
        }

        // Method 2: s_hash
        if (sHash) {
            try {
                def hash     = MessageDigest.getInstance('SHA-256').digest(xsmid.trim().bytes)
                def halfHash = Arrays.copyOfRange(hash, 0, 16)
                def computed = Base64.urlEncoder.withoutPadding().encodeToString(halfHash)
                logger.info('[Validate] s_hash JWT:      ' + sHash.trim())
                logger.info('[Validate] s_hash computed: ' + computed)
                if (computed == sHash.trim()) {
                    logger.info('[Validate] ✅ MATCH via s_hash')
                    def r = new Response(Status.OK)
                    r.headers.put('Content-Type', 'application/json')
                    r.entity.string = JsonOutput.toJson([
                        valid      : true,
                        decision   : 'APPROVED',
                        xsmid      : xsmid,
                        userId     : userId,
                        acr        : acr,
                        expiresAt  : exp,
                        matchMethod: 'S_HASH',
                        message    : 'HRT validated via s_hash'
                    ])
                    return r
                }
            } catch(e) {
                logger.error('[Validate] s_hash error: ' + e)
            }
        }

        logger.error('[Validate] ❌ MISMATCH — request: ' + xsmid + ' jwt: ' + jwtXsmid)
        def r = new Response(Status.UNAUTHORIZED)
        r.headers.put('Content-Type', 'application/json')
        r.entity.string = JsonOutput.toJson([
            valid        : false,
            error        : 'XSMID_MISMATCH',
            requestXsmid : xsmid,
            jwtXsmid     : jwtXsmid ?: 'NOT_IN_JWT'
        ])
        return r
    },
    { err ->
        logger.error('[Validate] http.send error: ' + err)
        def r = new Response(Status.INTERNAL_SERVER_ERROR)
        r.headers.put('Content-Type', 'application/json')
        r.entity.string = JsonOutput.toJson([valid:false, error:'CALL_FAILED', message:err?.getMessage()])
        return r
    }
)