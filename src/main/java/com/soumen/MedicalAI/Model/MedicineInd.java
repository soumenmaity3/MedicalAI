package com.soumen.MedicalAI.Model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "medicine_ind")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MedicineInd {

    @Id
    private Integer id;

    @Column(name = "drug_name")
    private String drugName;

    @Column(name = "drug_url")
    private String drugUrl;

    @Column(name = "drug_type")
    private String drugType;

    @Column(name = "prescription_required")
    private Boolean prescriptionRequired;

    @Column(name = "mrp")
    private Double mrp;

    @Column(name = "discount_percentage")
    private Double discountPercentage;

    @Column(name = "selling_price")
    private Double sellingPrice;

    @Column(name = "manufacturer")
    private String manufacturer;

    @Column(name = "marketer")
    private String marketer;

    @Column(name = "pack_size")
    private String packSize;

    @Column(name = "pack_type")
    private String packType;

    @Column(name = "storage_conditions")
    private String storageConditions;

    @Column(name = "uses")
    private String uses;

    @Column(name = "benefits")
    private String benefits;

    @Column(name = "how_it_works")
    private String howItWorks;

    @Column(name = "common_side_effects")
    private String commonSideEffects;

    @Column(name = "alcohol_interaction")
    private String alcoholInteraction;

    @Column(name = "pregnancy_safety")
    private String pregnancySafety;

    @Column(name = "breastfeeding_safety")
    private String breastfeedingSafety;

    @Column(name = "kidney_safety")
    private String kidneySafety;

    @Column(name = "liver_safety")
    private String liverSafety;

    @Column(name = "how_to_use")
    private String howToUse;

    @Column(name = "substitute_count")
    private Integer substituteCount;

    @Column(name = "substitute_list")
    private String substituteList;

    @Column(name = "chemical_class")
    private String chemicalClass;

    @Column(name = "habit_forming")
    private String habitForming;

    @Column(name = "action_class")
    private String actionClass;
}