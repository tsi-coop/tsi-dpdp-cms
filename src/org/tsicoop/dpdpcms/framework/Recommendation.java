package org.tsicoop.dpdpcms.framework;

import java.util.Arrays;

public class Recommendation {
    public String id;
    public String name;
    public String industry;
    public String state;
    public String city;

    public String[] attributes;


    public Recommendation(String id, String name, String industry, String state, String city, String[] attributes) {
        this.id = id;
        this.name = name;
        this.industry = industry;
        this.state = state;
        this.city = city;
        this.attributes = attributes;
    }

    @Override
    public String toString() {
        return String.format("BusinessMatch(id=%s, name='%s', industry='%s', state='%s', city=%s, attributes=%s)", id, name, industry, state, city, Arrays.toString(attributes));
    }
}

