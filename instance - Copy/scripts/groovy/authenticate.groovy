import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.util.UUID
import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status

def bodyText = request.entity.string
def body     = new JsonSlurper().parseText(bodyText ?: '{}')

def amount      = body?.amount      ?: 0
def currency    = body?.currency    ?: 'USD'
def toAccount   = body?.toAccount   ?: 'unknown'
def fromAccount = body?.fromAccount ?: 'unknown'
def deviceId    = body?.deviceId    ?: 'unknown'
def browserInfo = body?.browserInfo ?: 'unknown'

logger.info('[Auth] HRT Authenticate called - amount: ' + amount)

if (!amount || amount == 0) {
    def r = new Response(Status.BAD_REQUEST)
    r.headers.add('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([error:'MISSING_AMOUNT', message:'amount is required'])
    return r
}

if (!toAccount || toAccount == 'unknown') {
    def r = new Response(Status.BAD_REQUEST)
    r.headers.add('Content-Type', 'application/json')
    r.entity.string = JsonOutput.toJson([error:'MISSING_ACCOUNT', message:'toAccount is required'])
    return r
}

def xsmid    = UUID.randomUUID().toString()
def issuedAt = System.currentTimeMillis() / 1000 as long

logger.info('[Auth] xsmid generated: ' + xsmid)

def response = new Response(Status.OK)
response.headers.add('Content-Type', 'application/json')
response.entity.string = JsonOutput.toJson([
    xsmid    : xsmid,
    issuedAt : issuedAt,
    expiresIn: 3600,
    message  : 'Transaction identifier generated'
])
return response