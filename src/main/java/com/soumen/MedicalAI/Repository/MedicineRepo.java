package com.soumen.MedicalAI.Repository;

import com.soumen.MedicalAI.Model.MedicineInd;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MedicineRepo extends JpaRepository<MedicineInd, Integer> {

//    List<MedicineInd> findByDrugNameContainingIgnoreCase(String name);

    @Query(value = """
            SELECT * FROM medicine_ind
            WHERE similarity(drug_name, :name) > 0.3
            ORDER BY similarity(drug_name, :name) DESC
            LIMIT 10
            """, nativeQuery = true)
    List<MedicineInd> fuzzySearch(@Param("name") String name);

    @Query(value = "SELECT * FROM medicine_ind ORDER BY RAND() LIMIT :limit OFFSET :offset", nativeQuery = true)
    List<MedicineInd> fetchMedicines(int limit, int offset);
}
