package io.mosip.certify.mock.integration.service;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.api.util.ErrorConstants;
import io.mosip.certify.constants.VCFormats;
import io.mosip.certify.mock.integration.mocks.MdocGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.*;

@ConditionalOnProperty(value = "mosip.certify.integration.vci-plugin", havingValue = "MDocMockVCIssuancePlugin")
@Component
@Slf4j
public class MDocMockVCIssuancePlugin implements VCIssuancePlugin {
    @Value("${mosip.certify.mock.vciplugin.mdoc.issuer-key-cert:empty}")
    private String issuerKeyAndCertificate = null;

    @Override
    public VCResult<JsonLDObject> getVerifiableCredentialWithLinkedDataProof(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {
        log.error("not implemented the format {}", vcRequestDto);
        throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

    @Override
    public VCResult<String> getVerifiableCredential(VCRequestDto vcRequestDto, String holderId, Map<String, Object> identityDetails) throws VCIExchangeException {
        if (vcRequestDto.getFormat().equals(VCFormats.MSO_MDOC)) {
            VCResult<String> vcResult = new VCResult<>();
            String mdocVc;
            try {
                String documentNumber = getIndividualId(identityDetails);
                mdocVc = new MdocGenerator().generate(mockDataForMsoMdoc(documentNumber), holderId, issuerKeyAndCertificate);
            } catch (Exception e) {
                log.error("Exception on mdoc creation", e);
                throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
            }
            vcResult.setCredential(mdocVc);
            vcResult.setFormat(VCFormats.MSO_MDOC);
            return vcResult;
        }
        log.error("not implemented the format {}", vcRequestDto);
        throw new VCIExchangeException(ErrorConstants.NOT_IMPLEMENTED);
    }

    private String getIndividualId(Map<String, Object> identityDetails) throws VCIExchangeException {
        String individualId = (String) identityDetails.get("sub");
        if (individualId != null) {
            return individualId;
        }
        log.error("Error getting documentNumber - ID not found");
        throw new VCIExchangeException(ErrorConstants.VCI_EXCHANGE_FAILED);
    }

    private Map<String, Object> mockDataForMsoMdoc(String documentNumber) {
        Map<String, Object> data = new HashMap<>();
        log.info("Setting up the data for mDoc");
        data.put("family_name", "Agatha");
        data.put("given_name", "Joseph");
        data.put("birth_date", "1994-11-06");
        data.put("issuing_country", "IN");
        data.put("document_number", documentNumber);
        data.put("driving_privileges", new HashMap<>() {{
            put("vehicle_category_code", "A");
        }});
        return data;
    }
}
