/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/RsaKeyParameters.h>

using namespace Vnet::Cryptography;

RsaKeyParameters::RsaKeyParameters() { }

RsaKeyParameters::RsaKeyParameters(const RsaKeyParameters& params) {
    this->operator= (params);
}

RsaKeyParameters::RsaKeyParameters(RsaKeyParameters&& params) noexcept {
    this->operator= (std::move(params));
}

RsaKeyParameters::~RsaKeyParameters() { }

RsaKeyParameters& RsaKeyParameters::operator= (const RsaKeyParameters& params) {

    if (this != &params) {

        this->Modulus = params.Modulus;
        this->PublicExponent = params.PublicExponent;
        this->PrivateExponent = params.PrivateExponent;
        this->Prime1 = params.Prime1;
        this->Prime2 = params.Prime2;
        this->Exponent1 = params.Exponent1;
        this->Exponent2 = params.Exponent2;
        this->Coefficient = params.Coefficient;

    }

    return static_cast<RsaKeyParameters&>(*this);
}

RsaKeyParameters& RsaKeyParameters::operator= (RsaKeyParameters&& params) noexcept {

    if (this != &params) {

        this->Modulus = std::move(params.Modulus);
        this->PublicExponent = std::move(params.PublicExponent);
        this->PrivateExponent = std::move(params.PrivateExponent);
        this->Prime1 = std::move(params.Prime1);
        this->Prime2 = std::move(params.Prime2);
        this->Exponent1 = std::move(params.Exponent1);
        this->Exponent2 = std::move(params.Exponent2);
        this->Coefficient = std::move(params.Coefficient);

    }

    return static_cast<RsaKeyParameters&>(*this);
}

bool RsaKeyParameters::operator== (const RsaKeyParameters& params) const {

    if (this->Modulus != params.Modulus) return false;
    if (this->PublicExponent != params.PublicExponent) return false;
    if (this->PrivateExponent != params.PrivateExponent) return false;
    if (this->Prime1 != params.Prime1) return false;
    if (this->Prime2 != params.Prime2) return false;
    if (this->Exponent1 != params.Exponent1) return false;
    if (this->Exponent2 != params.Exponent2) return false;
    if (this->Coefficient != params.Coefficient) return false;
    
    return true;
}