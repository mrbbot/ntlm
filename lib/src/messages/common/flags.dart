const NTLM_NegotiateUnicode = 0x00000001;
const NTLM_NegotiateOEM = 0x00000002;
const NTLM_RequestTarget = 0x00000004;
const NTLM_Unknown9 = 0x00000008;
const NTLM_NegotiateSign = 0x00000010;
const NTLM_NegotiateSeal = 0x00000020;
const NTLM_NegotiateDatagram = 0x00000040;
const NTLM_NegotiateLanManagerKey = 0x00000080;
const NTLM_Unknown8 = 0x00000100;
const NTLM_NegotiateNTLM = 0x00000200;
const NTLM_NegotiateNTOnly = 0x00000400;
const NTLM_Anonymous = 0x00000800;
const NTLM_NegotiateOemDomainSupplied = 0x00001000;
const NTLM_NegotiateOemWorkstationSupplied = 0x00002000;
const NTLM_Unknown6 = 0x00004000;
const NTLM_NegotiateAlwaysSign = 0x00008000;
const NTLM_TargetTypeDomain = 0x00010000;
const NTLM_TargetTypeServer = 0x00020000;
const NTLM_TargetTypeShare = 0x00040000;
const NTLM_NegotiateExtendedSecurity = 0x00080000;
const NTLM_NegotiateIdentify = 0x00100000;
const NTLM_Unknown5 = 0x00200000;
const NTLM_RequestNonNTSessionKey = 0x00400000;
const NTLM_NegotiateTargetInfo = 0x00800000;
const NTLM_Unknown4 = 0x01000000;
const NTLM_NegotiateVersion = 0x02000000;
const NTLM_Unknown3 = 0x04000000;
const NTLM_Unknown2 = 0x08000000;
const NTLM_Unknown1 = 0x10000000;
const NTLM_Negotiate128 = 0x20000000;
const NTLM_NegotiateKeyExchange = 0x40000000;
const NTLM_Negotiate56 = 0x80000000;

const NTLM_TYPE1_FLAGS = NTLM_NegotiateUnicode +
    NTLM_NegotiateOEM +
    NTLM_RequestTarget +
    NTLM_NegotiateNTLM +
    NTLM_NegotiateOemDomainSupplied +
    NTLM_NegotiateOemWorkstationSupplied +
    NTLM_NegotiateAlwaysSign +
    NTLM_NegotiateExtendedSecurity +
    NTLM_NegotiateVersion +
    NTLM_Negotiate128 +
    NTLM_Negotiate56;

const NTLM_TYPE2_FLAGS = NTLM_NegotiateUnicode +
    NTLM_RequestTarget +
    NTLM_NegotiateNTLM +
    NTLM_NegotiateAlwaysSign +
    NTLM_NegotiateExtendedSecurity +
    NTLM_NegotiateTargetInfo +
    NTLM_NegotiateVersion +
    NTLM_Negotiate128 +
    NTLM_Negotiate56;
