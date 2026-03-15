package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.MedicineInd;
import com.soumen.MedicalAI.Repository.MedicineRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MedicineService {
    @Autowired
    private MedicineRepo repo;

    public List<MedicineInd> getMedicines(int offset, int limit) {
        return repo.fetchMedicines(limit, offset);
    }

}
