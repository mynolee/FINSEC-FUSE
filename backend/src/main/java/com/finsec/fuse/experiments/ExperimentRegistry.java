package com.finsec.fuse.experiments;

import com.finsec.fuse.common.*;
import java.util.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

@Component
public class ExperimentRegistry {
    private final Json json;
    public ExperimentRegistry(Json json){this.json=json;}
    public record Selection(String fixtureSetId,String hash,List<Map<String,Object>> cases){}
    @SuppressWarnings("unchecked")
    public Selection select(String fixtureSetId,List<String> ids) {
        if(!Set.of("mvp-security-v1","security-evaluation-v1").contains(fixtureSetId))
            throw new ApiException(400,"INVALID_REQUEST","Unknown fixture set.");
        Map<String,Object> manifest;
        try(var in=new ClassPathResource("evaluation/"+fixtureSetId+".json").getInputStream()) {manifest=json.map(in.readAllBytes());}
        catch(Exception failure){throw new IllegalStateException("Registered fixture resource unavailable",failure);}
        var cases=(List<Map<String,Object>>)manifest.get("cases");
        var selected=new ArrayList<Map<String,Object>>();var unique=new HashSet<String>();
        if(ids.isEmpty())selected.addAll(cases);
        else for(String id:ids) {
            if(!unique.add(id))throw new ApiException(400,"INVALID_REQUEST","Duplicate case ID.");
            selected.add(cases.stream().filter(c->id.equals(c.get("caseId"))).findFirst()
                .orElseThrow(()->new ApiException(400,"INVALID_REQUEST","Unregistered case ID.")));
        }
        return new Selection(fixtureSetId,json.hash(sorted(manifest)),List.copyOf(selected));
    }
    @SuppressWarnings("unchecked")
    public static Object sorted(Object value) {
        if(value instanceof Map<?,?> map){var result=new TreeMap<String,Object>();map.forEach((k,v)->result.put(k.toString(),sorted(v)));return result;}
        if(value instanceof List<?> list)return list.stream().map(ExperimentRegistry::sorted).toList();
        return value;
    }
}
