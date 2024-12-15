package de.karaca.csrparser.decoder;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class GeneralName {
    public static final int TAG_DNS = 2;
    public static final int TAG_IP = 7;

    private final int tag;
    private final String value;
}
