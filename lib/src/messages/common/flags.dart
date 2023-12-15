const ntlmNegotiateUnicode = 0x00000001;
const ntlmNegotiateOEM = 0x00000002;
const ntlmRequestTarget = 0x00000004;
const ntlmUnknown9 = 0x00000008;
const ntlmNegotiateSign = 0x00000010;
const ntlmNegotiateSeal = 0x00000020;
const ntlmNegotiateDatagram = 0x00000040;
const ntlmNegotiateLanManagerKey = 0x00000080;
const ntlmUnknown8 = 0x00000100;
const ntlmNegotiateNTLM = 0x00000200;
const ntlmNegotiateNTOnly = 0x00000400;
const ntlmAnonymous = 0x00000800;
const ntlmNegotiateOemDomainSupplied = 0x00001000;
const ntlmNegotiateOemWorkstationSupplied = 0x00002000;
const ntlmUnknown6 = 0x00004000;
const ntlmNegotiateAlwaysSign = 0x00008000;
const ntlmTargetTypeDomain = 0x00010000;
const ntlmTargetTypeServer = 0x00020000;
const ntlmTargetTypeShare = 0x00040000;
const ntlmNegotiateExtendedSecurity = 0x00080000;
const ntlmNegotiateIdentify = 0x00100000;
const ntlmUnknown5 = 0x00200000;
const ntlmRequestNonNTSessionKey = 0x00400000;
const ntlmNegotiateTargetInfo = 0x00800000;
const ntlmUnknown4 = 0x01000000;
const ntlmNegotiateVersion = 0x02000000;
const ntlmUnknown3 = 0x04000000;
const ntlmUnknown2 = 0x08000000;
const ntlmUnknown1 = 0x10000000;
const ntlmNegotiate128 = 0x20000000;
const ntlmNegotiateKeyExchange = 0x40000000;
const ntlmNegotiate56 = 0x80000000;

const ntlmType1Flags = ntlmNegotiateUnicode +
    ntlmNegotiateOEM +
    ntlmRequestTarget +
    ntlmNegotiateNTLM +
    ntlmNegotiateOemDomainSupplied +
    ntlmNegotiateOemWorkstationSupplied +
    ntlmNegotiateAlwaysSign +
    ntlmNegotiateExtendedSecurity +
    ntlmNegotiateVersion +
    ntlmNegotiate128 +
    ntlmNegotiate56;

const ntlmType2Flags = ntlmNegotiateUnicode +
    ntlmRequestTarget +
    ntlmNegotiateNTLM +
    ntlmNegotiateAlwaysSign +
    ntlmNegotiateExtendedSecurity +
    ntlmNegotiateTargetInfo +
    ntlmNegotiateVersion +
    ntlmNegotiate128 +
    ntlmNegotiate56;
