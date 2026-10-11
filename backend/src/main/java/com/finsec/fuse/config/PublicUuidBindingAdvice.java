package com.finsec.fuse.config;

import java.beans.PropertyEditorSupport;
import java.util.UUID;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

/** Spring falls back to UUIDEditor after conversion failure; make that path strict too. */
@ControllerAdvice
public final class PublicUuidBindingAdvice {
    @InitBinder public void canonicalUuidEditor(WebDataBinder binder) {
        binder.registerCustomEditor(UUID.class,new PropertyEditorSupport() {
            @Override public void setAsText(String value) {
                setValue(PublicUuidConfiguration.parseCanonical(value));
            }
        });
    }
}
