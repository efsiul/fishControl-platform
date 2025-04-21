package com.fc.supplyservice.services;

import com.fc.supplyservice.models.ESupplyType;
import com.fc.supplyservice.models.SupplyEntity;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface SupplyDetailsService {

    List<SupplyEntity> getAllSupplies();
    Optional<SupplyEntity> getSupplyById(Long id);
    SupplyEntity createSupply(SupplyEntity supply);
    SupplyEntity updateSupply(Long id, SupplyEntity supply);
    void deleteSupply(Long id);

    // métodos para consultas específicas
    List<SupplyEntity> getSuppliesByType(ESupplyType type);
    List<SupplyEntity> getSuppliesByStage(String stage);
    Map<ESupplyType, Integer> getInventory();

    // Modificado para devolver una lista
    List<SupplyEntity> getSupplyByName(String name);
}