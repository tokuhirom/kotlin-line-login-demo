package com.example.demo

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.runApplication
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.util.UriComponentsBuilder
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession

data class LineLoginTokenResponse(
        val access_token: String,
        val expires_in: Long,
        val id_token: String,
        val refresh_token: String,
        val scope: String,
        val token_type: String
)

@Component
@ConfigurationProperties("line-login")
class LineLoginProperties {
    var clientId: String? = null
    var clientSecret: String? = null
}

@RestController
class MyController(val lineLoginProperties: LineLoginProperties, val objectMapper: ObjectMapper) {
    @GetMapping("/", produces = arrayOf("text/html"))
    fun index(session: HttpSession, model: Model, request: HttpServletRequest): String {
        val redirectUrl = UriComponentsBuilder
                .fromUriString(request.requestURL.toString())
                .path("/callback")
                .build().toUriString()

        // We don't need to refresh state.
        val state = fun(): String {
            val currentState = session.getAttribute("state")
            if (currentState is String) {
                return currentState
            }

            val newState = UUID.randomUUID().toString()
            session.setAttribute("state", newState)
            return newState
        }()

        // We should refresh nonce every time.
        val nonce = fun(): String {
            val nonce = UUID.randomUUID().toString()
            session.setAttribute(nonce, true)
            return nonce
        }()

        val url = UriComponentsBuilder.fromUriString("https://access.line.me/oauth2/v2.1/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", lineLoginProperties.clientId)
                .queryParam("redirect_uri", redirectUrl)
                .queryParam("state", state)
                .queryParam("scope", "openid profile")
                .queryParam("nonce", nonce)
                .build()
                .toUriString()

        return """<a href="$url">Login</a>"""
    }

    @GetMapping("/callback", produces = arrayOf(MediaType.APPLICATION_JSON_VALUE))
    fun callback(
            @RequestParam("code") code: String?,
            @RequestParam("state", required = false) state: String?,
            @RequestParam("friendship_status_changed", required = false) friendshipStatusChanged: Boolean?,
            @RequestParam("error", required = false) error: String?,
            @RequestParam("error_description", required = false) errorDescription: String?,
            servletRequest: HttpServletRequest,
            session: HttpSession): Map<String, String?> {
        if (error != null) {
            return mapOf(
                    "error" to error,
                    "errorDescription" to errorDescription
            )
        }

        val sessionState = session.getAttribute("state")
        if (!(sessionState is String && sessionState == state)) {
            // TODO show error page?
            throw IllegalStateException("Invalid state")
        }

        val response = fun(): LineLoginTokenResponse {
            val formBody = FormBody.Builder()
                    .add("grant_type", "authorization_code")
                    .add("code", code)
                    .add("redirect_uri", servletRequest.requestURL.toString())
                    .add("client_id", lineLoginProperties.clientId)
                    .add("client_secret", lineLoginProperties.clientSecret)
                    .build()

            val request = Request.Builder()
                    .post(formBody)
                    .url("https://api.line.me/oauth2/v2.1/token")
                    .build()
            val response = OkHttpClient()
                    .newCall(request)
                    .execute()
            if (!response.isSuccessful) {
                throw IllegalStateException("LINE Login returns an error: " + response.message())
            }
            return objectMapper.readValue(response.body().bytes(), LineLoginTokenResponse::class.java)
        }()
        val jwt = JWTParser.parse(response.id_token)
        if (!(jwt as SignedJWT).verify(MACVerifier(lineLoginProperties.clientSecret))) {
            throw Exception("Invalid signature")
        }

        // check nonce
        val gotNonce = jwt.jwtClaimsSet.getStringClaim("nonce")
        val nonceValue = session.getAttribute(gotNonce)
        if (!(nonceValue is Boolean)) {
            throw IllegalStateException("Illegal nonce")
        }

        return mapOf(
                "userId" to jwt.jwtClaimsSet.subject,
                "userName" to jwt.jwtClaimsSet.getStringClaim("name"),
                "picture" to jwt.jwtClaimsSet.getStringClaim("picture")
        )
    }
}

@SpringBootApplication
class DemoApplication

fun main(args: Array<String>) {
    runApplication<DemoApplication>(*args)
}
