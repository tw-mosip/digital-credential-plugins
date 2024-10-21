package io.mosip.certify.util;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class CBORConverter1 {
//    public static DataItem toDataItem(Object value) {
//        if (value instanceof DataItem) {
//            return (DataItem) value;
//        } else if (value instanceof String) {
//            return new UnicodeString((String) value);
//        } else if (value instanceof Integer) {
//            return new UnsignedInteger(((Integer) value).longValue());
//        } else if (value instanceof Long) {
//            return new UnsignedInteger((Long) value);
//        } else if (value instanceof Boolean) {
//            return ((Boolean) value) ? SimpleValue.TRUE : SimpleValue.FALSE;
//        } else if (value instanceof Map<?, ?>) {
//            Map cborMap = new Map();
//            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
//                cborMap.put(new UnicodeString((String) entry.getKey()), toDataItem(entry.getValue()));
//            }
//            return cborMap;
//        } else if (value instanceof List<?>) {
//            Array cborArray = new Array();
//            for (Object item : (List<?>) value) {
//                cborArray.add(toDataItem(item));
//            }
//            return cborArray;
//        } else if (value instanceof Object[]) {
//            Array cborArray = new Array();
//            for (Object item : (Object[]) value) {
//                cborArray.add(toDataItem(item));
//            }
//            return cborArray;
//        } else if (value instanceof byte[]) {
//            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream((byte[]) value);
//            try {
//                List<DataItem> dataItems = new CborDecoder(byteArrayInputStream).decode();
//                return dataItems.isEmpty() ? null : dataItems.get(0);
//            } catch (IOException e) {
//                throw new IllegalArgumentException("Failed to decode byte array", e);
//            }
//        } else {
//            throw new IllegalArgumentException("Unsupported value: " + value + " " + value.getClass().getSimpleName());
//        }
//    }
}
