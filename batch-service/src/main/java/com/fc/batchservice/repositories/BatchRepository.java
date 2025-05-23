package com.fc.batchservice.repositories;

import com.fc.batchservice.models.BatchEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface BatchRepository extends CrudRepository<BatchEntity, Long> {

    Optional<BatchEntity> findByBatchId(Long batchId);

    @Query("select s from BatchEntity s where s.batchId = ?1")
    Optional<BatchEntity> getBatchByBatchId(Long batchId);
}
