import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.security.MessageDigest
import java.util.Base64
import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

def AIC_BASE      = 'https://openam-kpmg-enablement.forgeblocks.com'
def REALM         = '/am/oauth2/realms/root/realms/alpha'
def CLIENT_ID     = 'ig-poc-client'
def CLIENT_SECRET = 'Password@123'

// ── PARSE REQUEST BODY ────────────────────────────────────────────────────────
// Client spec request format:
// {
//   "claims_on_response": false,
//   "params": { "xsmid": "<uuid>" },
//   "token": "<jwt>",
//   "policy": "dtb_hrt_auth"
// }
def jwt              = ''
def xsmid            = ''
def policy           = ''
def claimsOnResponse = false

try {
    def bodyText     = request.entity.string ?: '{}'
    def body         = new JsonSlurper().parseText(bodyText)

    jwt              = body?.token              ?: ''
    claimsOnResponse = body?.claims_on_response ?: false
    policy           = body?.policy             ?: ''

    // xsmid is inside params object
    def params       = body?.params             ?: [:]
    xsmid            = params?.xsmid            ?: ''

    logger.info('[Validate] policy:             ' + policy)
    logger.info('[Validate] claims_on_response: ' + claimsOnResponse)
    logger.info('[Validate] xsmid from params:  ' + xsmid)
    logger.info('[Validate] token length:       ' + jwt.length())

} catch(e) {
    logger.error('[Validate] Body parse error: ' + e)
    def r = new Response(Status.BAD_REQUEST)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([
        error_message: 'Invalid JSON request body',
        data         : '',
        error_code   : 1
    ])
    return r
}

// ── VALIDATE INPUTS ───────────────────────────────────────────────────────────
if (!jwt || jwt.trim().length() == 0) {
    logger.error('[Validate] token is missing')
    def r = new Response(Status.BAD_REQUEST)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([
        error_message: 'token is required',
        data         : '',
        error_code   : 1
    ])
    return r
}

if (!xsmid || xsmid.trim().length() == 0) {
    logger.error('[Validate] params.xsmid is missing')
    def r = new Response(Status.BAD_REQUEST)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([
        error_message: 'params.xsmid is required',
        data         : '',
        error_code   : 1
    ])
    return r
}

// ── DECODE JWT LOCALLY ────────────────────────────────────────────────────────
def jwtClaims = [:]
try {
    def parts  = jwt.trim().split('\\.')
    if (parts.length < 3) throw new Exception('Invalid JWT format')
    def pad    = parts[1] + '=' * ((4 - parts[1].length() % 4) % 4)
    jwtClaims  = new JsonSlurper().parseText(
                     new String(Base64.urlDecoder.decode(pad), 'UTF-8')
                 )
    logger.info('[Validate] JWT xsmid:  ' + (jwtClaims?.xsmid  ?: 'NOT PRESENT'))
    logger.info('[Validate] JWT acr:    ' + (jwtClaims?.acr    ?: 'n/a'))
    logger.info('[Validate] JWT sub:    ' + (jwtClaims?.sub    ?: 'n/a'))
    logger.info('[Validate] JWT exp:    ' + (jwtClaims?.exp    ?: 'n/a'))
    logger.info('[Validate] JWT s_hash: ' + (jwtClaims?.s_hash ?: 'n/a'))
} catch(e) {
    logger.error('[Validate] JWT decode error: ' + e)
    def r = new Response(Status.OK)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([
        error_message: 'JWT decode failed',
        data         : '',
        error_code   : 1
    ])
    return r
}

// ── CHECK EXPIRY ──────────────────────────────────────────────────────────────
def now = (long)(System.currentTimeMillis() / 1000)
def exp = jwtClaims?.exp ? (jwtClaims.exp as long) : 0L
logger.info('[Validate] now=' + now + ' exp=' + exp + ' diff=' + (exp - now) + 's')

if (exp > 0 && now > exp) {
    logger.error('[Validate] JWT EXPIRED')
    def r = new Response(Status.OK)
    r.headers.put('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([
        error_message: 'Token has expired',
        data         : '',
        error_code   : 5002
    ])
    return r
}

// ── CALL AIC idtokeninfo ──────────────────────────────────────────────────────
logger.info('[Validate] Calling AIC /idtokeninfo...')

def idInfoReq = new Request()
idInfoReq.method = 'POST'
idInfoReq.uri    = new URI("${AIC_BASE}${REALM}/idtokeninfo")
idInfoReq.headers.put('Content-Type', 'application/x-www-form-urlencoded')
idInfoReq.entity.string =
    'client_id='      + URLEncoder.encode(CLIENT_ID,     'UTF-8') +
    '&client_secret=' + URLEncoder.encode(CLIENT_SECRET, 'UTF-8') +
    '&id_token='      + URLEncoder.encode(jwt.trim(),    'UTF-8')

return http.send(idInfoReq).then(
    { resp ->
        def raw        = resp.entity.string
        def statusCode = resp.status.code as int

        logger.info('[Validate] idtokeninfo status:   ' + statusCode)
        logger.info('[Validate] idtokeninfo response: ' + raw)

        if (statusCode != 200) {
            logger.error('[Validate] AIC rejected JWT: ' + statusCode)
            def r = new Response(Status.OK)
            r.headers.put('Content-Type', 'application/json')
            r.entity.string = JsonOutput.toJson([
                error_message: 'JWT validation failed',
                data         : '',
                error_code   : 1
            ])
            return r
        }

        def claims   = new JsonSlurper().parseText(raw)
        def jwtXsmid = claims?.xsmid  ? claims.xsmid.toString()  : ''
        def sHash    = claims?.s_hash ? claims.s_hash.toString() : ''

        logger.info('[Validate] AIC validated JWT ✅')
        logger.info('[Validate] xsmid in JWT:      ' + (jwtXsmid ?: 'NOT PRESENT'))
        logger.info('[Validate] xsmid in params:   ' + xsmid)

        // ── METHOD 1: Direct xsmid claim match ───────────────────────────────
        if (jwtXsmid && jwtXsmid.trim() == xsmid.trim()) {
            logger.info('[Validate] ✅ MATCH via JWT claim — APPROVED')
            def r = new Response(Status.OK)
            r.headers.put('Content-Type', 'application/json')
            r.entity.string = JsonOutput.toJson([
                error_message: '',
                data         : '',
                error_code   : 0
            ])
            return r
        }

        // ── METHOD 2: s_hash verification ────────────────────────────────────
        if (sHash && sHash.trim().length() > 0) {
            try {
                def hash     = MessageDigest.getInstance('SHA-256').digest(xsmid.trim().bytes)
                def halfHash = Arrays.copyOfRange(hash, 0, 16)
                def computed = Base64.urlEncoder.withoutPadding().encodeToString(halfHash)
                logger.info('[Validate] s_hash JWT:      ' + sHash.trim())
                logger.info('[Validate] s_hash computed: ' + computed)
                if (computed == sHash.trim()) {
                    logger.info('[Validate] ✅ MATCH via s_hash — APPROVED')
                    def r = new Response(Status.OK)
                    r.headers.put('Content-Type', 'application/json')
                    r.entity.string = JsonOutput.toJson([
                        error_message: '',
                        data         : '',
                        error_code   : 0
                    ])
                    return r
                }
                logger.error('[Validate] s_hash MISMATCH ❌')
            } catch(e) {
                logger.error('[Validate] s_hash error: ' + e)
            }
        }

        // ── BOTH FAILED ───────────────────────────────────────────────────────
        logger.error('[Validate] ❌ xsmid MISMATCH')
        def r = new Response(Status.OK)
        r.headers.put('Content-Type', 'application/json')
        r.entity.string = JsonOutput.toJson([
            error_message: 'JWT validation failed — xsmid mismatch',
            data         : '',
            error_code   : 1
        ])
        return r
    },
    { err ->
        logger.error('[Validate] idtokeninfo call failed: ' + err)
        def r = new Response(Status.INTERNAL_SERVER_ERROR)
        r.headers.put('Content-Type', 'application/json')
        r.entity.string = JsonOutput.toJson([
            error_message: 'IDG internal error: ' + (err?.getMessage() ?: 'Unknown'),
            data         : '',
            error_code   : 1
        ])
        return r
    }
)