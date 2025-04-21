package com.fc.supplyservice.repositories;

import com.fc.supplyservice.models.ESupplyType;
import com.fc.supplyservice.models.SupplyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SupplyRepository extends JpaRepository<SupplyEntity, Long> {

    // Cambiado para devolver una lista en lugar de Optional
    List<SupplyEntity> findBySuppliesName(String suppliesName);

    // Actualizado para devolver una lista
    @Query("select s from SupplyEntity s where s.suppliesName = ?1")
    List<SupplyEntity> getName(String suppliesName);

    List<SupplyEntity> findByType(ESupplyType type);
    List<SupplyEntity> findByStage(String stage);
}