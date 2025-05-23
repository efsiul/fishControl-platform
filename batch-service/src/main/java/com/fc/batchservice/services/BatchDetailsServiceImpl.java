package com.fc.batchservice.services;

import com.fc.batchservice.dtos.CreateBatchDTO;
import com.fc.batchservice.models.BatchEntity;
import com.fc.batchservice.repositories.BatchRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class BatchDetailsServiceImpl implements BatchDetailsService {

    private final BatchRepository batchRepository;

    public BatchDetailsServiceImpl(BatchRepository batchRepository) {
        this.batchRepository = batchRepository;
    }

    @Override
    public BatchEntity createBatch(CreateBatchDTO createBatchDTO) {

        BatchEntity batch = new BatchEntity();
        batch.setQuantityAnimalsPerBatch(createBatchDTO.getQuantityAnimalsPerBatch());
        batch.setAverageWeightPerAnimal(createBatchDTO.getAverageWeightPerAnimal());
        batch.setEntryDate(createBatchDTO.getEntryDate().atStartOfDay());
        batch.setBatchAge(createBatchDTO.getBatchAge());
        batch.setAnimalsRemoved(0); // Inicialmente no hay animales removidos

        return batchRepository.save(batch);

    }

    //Buscar un lote por Id
    @Override
    public Optional<BatchEntity> getBatchById(Long id) {
        return batchRepository.findById(id);
    }

    //Obtener todos los lotes
    @Override
    public List<BatchEntity> getAllBatches() {
        return (List<BatchEntity>) batchRepository.findAll();
    }

    //Actualizar un lote existente
    @Override
    public BatchEntity updateBatch(Long id, Integer quantityAnimalsPerBatch, Double averageWeightPerAnimal, Integer batchAge) {
        Optional<BatchEntity> optionalBatch = batchRepository.findById(id);
        if (optionalBatch.isPresent()) {
            BatchEntity batch = optionalBatch.get();
            batch.setQuantityAnimalsPerBatch(quantityAnimalsPerBatch);
            batch.setAverageWeightPerAnimal(averageWeightPerAnimal);
            batch.setBatchAge(batchAge);
            return batchRepository.save(batch);
        }else {
            throw new RuntimeException("Lote no encontrado con ID: " + id);
        }
    }

    //Eliminar un lote
    @Override
    public void deleteBatch(Long id) {
        batchRepository.deleteById(id);
    }

    //Remover animales de un lote
    @Override
    public BatchEntity removeAnimalsFromBatch(Long id, Integer animalsToRemove) {
        Optional<BatchEntity> optionalBatch = batchRepository.findById(id);

        if (optionalBatch.isPresent()) {

            BatchEntity batch = optionalBatch.get();

            Integer currentQuantity = batch.getQuantityAnimalsPerBatch();
            if(animalsToRemove > currentQuantity) {
                throw new IllegalArgumentException("No se pueden remover más animales de los que hay en el lote.");
            }

            batch.setQuantityAnimalsPerBatch(currentQuantity - animalsToRemove);
            batch.setAnimalsRemoved(batch.getAnimalsRemoved() + animalsToRemove);

            return batchRepository.save(batch);
        } else {
            throw new RuntimeException("Lote no encontrado con ID: " + id);
        }
    }
}
