<?php

declare(strict_types=1);

namespace DigitalCz\OpenIDConnect;

use DigitalCz\OpenIDConnect\Param\Params;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

final class ProviderMetadata extends Params
{
    public const ISSUER = 'issuer';
    public const AUTHORIZATION_ENDPOINT = 'authorization_endpoint';
    public const TOKEN_ENDPOINT = 'token_endpoint';
    public const USERINFO_ENDPOINT = 'userinfo_endpoint';
    public const JWKS_URI = 'jwks_uri';
    public const REGISTRATION_ENDPOINT = 'registration_endpoint';
    public const SCOPES_SUPPORTED = 'scopes_supported';
    public const RESPONSE_TYPES_SUPPORTED = 'response_types_supported';
    public const RESPONSE_MODES_SUPPORTED = 'response_modes_supported';
    public const GRANT_TYPES_SUPPORTED = 'grant_types_supported';
    public const ACR_VALUES_SUPPORTED = 'acr_values_supported';
    public const SUBJECT_TYPES_SUPPORTED = 'subject_types_supported';
    public const ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = 'id_token_signing_alg_values_supported';
    public const ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED = 'id_token_encryption_alg_values_supported';
    public const ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED = 'id_token_encryption_enc_values_supported';
    public const USERINFO_SIGNING_ALG_VALUES_SUPPORTED = 'userinfo_signing_alg_values_supported';
    public const USERINFO_ENCRYPTION_ALG_VALUES_SUPPORTED = 'userinfo_encryption_alg_values_supported';
    public const USERINFO_ENCRYPTION_ENC_VALUES_SUPPORTED = 'userinfo_encryption_enc_values_supported';
    public const REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = 'request_object_signing_alg_values_supported';
    public const REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED = 'request_object_encryption_alg_values_supported';
    public const REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED = 'request_object_encryption_enc_values_supported';
    public const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = 'token_endpoint_auth_methods_supported';
    public const TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = 'token_endpoint_auth_signing_alg_values_supported';
    public const DISPLAY_VALUES_SUPPORTED = 'display_values_supported';
    public const CLAIM_TYPES_SUPPORTED = 'claim_types_supported';
    public const CLAIMS_SUPPORTED = 'claims_supported';
    public const SERVICE_DOCUMENTATION = 'service_documentation';
    public const CLAIMS_LOCALES_SUPPORTED = 'claims_locales_supported';
    public const UI_LOCALES_SUPPORTED = 'ui_locales_supported';
    public const CLAIMS_PARAMETER_SUPPORTED = 'claims_parameter_supported';
    public const REQUEST_PARAMETER_SUPPORTED = 'request_parameter_supported';
    public const REQUEST_URI_PARAMETER_SUPPORTED = 'request_uri_parameter_supported';
    public const REQUIRE_REQUEST_URI_REGISTRATION = 'require_request_uri_registration';
    public const OP_POLICY_URI = 'op_policy_uri';
    public const OP_TOS_URI = 'op_tos_uri';

    /**
     * @param array<string, mixed> $metadata
     * @param JWKSet<JWK>|null $jwks
     */
    public function __construct(array $metadata, private ?JWKSet $jwks = null)
    {
        parent::__construct($metadata);
    }

    public function issuer(): string
    {
        return $this->getString(self::ISSUER);
    }

    public function authorizationEndpoint(): string
    {
        return $this->getString(self::AUTHORIZATION_ENDPOINT);
    }

    public function tokenEndpoint(): ?string
    {
        return $this->get(self::TOKEN_ENDPOINT);
    }

    public function userinfoEndpoint(): ?string
    {
        return $this->get(self::USERINFO_ENDPOINT);
    }

    public function jwksUri(): string
    {
        return $this->getString(self::JWKS_URI);
    }

    public function registrationEndpoint(): ?string
    {
        return $this->get(self::REGISTRATION_ENDPOINT);
    }

    /** @return string[] */
    public function scopesSupported(): array
    {
        return $this->get(self::SCOPES_SUPPORTED, []);
    }

    /** @return string[] */
    public function responseTypesSupported(): array
    {
        return $this->get(self::RESPONSE_TYPES_SUPPORTED, []);
    }

    /** @return string[] */
    public function responseModesSupported(): array
    {
        return $this->get(self::RESPONSE_MODES_SUPPORTED, ['query', 'fragment']);
    }

    /** @return string[] */
    public function grantTypesSupported(): array
    {
        return $this->get(self::GRANT_TYPES_SUPPORTED, ['authorization_code', 'implicit']);
    }

    /** @return string[] */
    public function acrValuesSupported(): array
    {
        return $this->get(self::ACR_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function subjectTypesSupported(): array
    {
        return $this->get(self::SUBJECT_TYPES_SUPPORTED, []);
    }

    /** @return string[] */
    public function idTokenSigningAlgValuesSupported(): array
    {
        return $this->get(self::ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function idTokenEncryptionAlgValuesSupported(): array
    {
        return $this->get(self::ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function idTokenEncryptionEncValuesSupported(): array
    {
        return $this->get(self::ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function userinfoSigningAlgValuesSupported(): array
    {
        return $this->get(self::USERINFO_SIGNING_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function userinfoEncryptionAlgValuesSupported(): array
    {
        return $this->get(self::USERINFO_ENCRYPTION_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function userinfoEncryptionEncValuesSupported(): array
    {
        return $this->get(self::USERINFO_ENCRYPTION_ENC_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function requestObjectSigningAlgValuesSupported(): array
    {
        return $this->get(self::REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function requestObjectEncryptionAlgValuesSupported(): array
    {
        return $this->get(self::REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function requestObjectEncryptionEncValuesSupported(): array
    {
        return $this->get(self::REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function tokenEndpointAuthMethodsSupported(): array
    {
        return $this->get(self::TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, ['client_secret_basic']);
    }

    /** @return string[] */
    public function tokenEndpointAuthSigningAlgValuesSupported(): array
    {
        return $this->get(self::TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function displayValuesSupported(): array
    {
        return $this->get(self::DISPLAY_VALUES_SUPPORTED, []);
    }

    /** @return string[] */
    public function claimTypesSupported(): array
    {
        return $this->get(self::CLAIM_TYPES_SUPPORTED, []);
    }

    /** @return string[] */
    public function claimsSupported(): array
    {
        return $this->get(self::CLAIMS_SUPPORTED, []);
    }

    public function serviceDocumentation(): string
    {
        return $this->get(self::SERVICE_DOCUMENTATION);
    }

    /** @return string[] */
    public function claimsLocalesSupported(): array
    {
        return $this->get(self::CLAIMS_LOCALES_SUPPORTED, []);
    }

    /** @return string[] */
    public function uiLocalesSupported(): array
    {
        return $this->get(self::UI_LOCALES_SUPPORTED, []);
    }

    public function claimsParameterSupported(): bool
    {
        return $this->getBool(self::CLAIMS_PARAMETER_SUPPORTED, false);
    }

    public function requestParameterSupported(): bool
    {
        return $this->getBool(self::REQUEST_PARAMETER_SUPPORTED, false);
    }

    public function requestUriParameterSupported(): bool
    {
        return $this->getBool(self::REQUEST_URI_PARAMETER_SUPPORTED, false);
    }

    public function requireRequestUriRegistration(): bool
    {
        return $this->getBool(self::REQUIRE_REQUEST_URI_REGISTRATION, false);
    }

    public function opPolicyUri(): string
    {
        return $this->get(self::OP_POLICY_URI);
    }

    public function opTosUri(): string
    {
        return $this->get(self::OP_TOS_URI);
    }

    /**
     * @return JWKSet<JWK>|null
     */
    public function getJwks(): ?JWKSet
    {
        return $this->jwks;
    }
}
