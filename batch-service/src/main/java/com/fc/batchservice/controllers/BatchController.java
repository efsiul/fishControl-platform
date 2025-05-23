package com.fc.batchservice.controllers;

import com.fc.batchservice.dtos.CreateBatchDTO;
import com.fc.batchservice.dtos.UpdateBatchRequest;
import com.fc.batchservice.models.BatchEntity;
import com.fc.batchservice.services.BatchDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/batches")
public class BatchController {

    private final BatchDetailsService batchDetailsService;

    @Autowired
    public BatchController(BatchDetailsService batchDetailsService) {
        this.batchDetailsService = batchDetailsService;
    }

    /**
     * Crea un nuevo lote.
     */
    @PostMapping
    public ResponseEntity<BatchEntity> createBatch(@RequestBody CreateBatchDTO createBatchDTO) {
        BatchEntity newBatch = batchDetailsService.createBatch(createBatchDTO);
        return new ResponseEntity<>(newBatch, HttpStatus.CREATED);
    }

    /**
     * Obtiene un lote por ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<BatchEntity> getBatchById(@PathVariable Long id) {
        Optional<BatchEntity> batch = batchDetailsService.getBatchById(id);
        return batch.map(ResponseEntity::ok)
                .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    /**
     * Lista todos los lotes.
     */
    @GetMapping
    public ResponseEntity<List<BatchEntity>> getAllBatches() {
        List<BatchEntity> batches = batchDetailsService.getAllBatches();
        return new ResponseEntity<>(batches, HttpStatus.OK);
    }

    /**
     * Actualiza un lote existente.
     */
    @PutMapping("/{id}")
    public ResponseEntity<BatchEntity> updateBatch(
            @PathVariable Long id,
            @RequestBody UpdateBatchRequest updateBatchRequest) {
        BatchEntity updatedBatch = batchDetailsService.updateBatch(
                id,
                updateBatchRequest.getQuantityAnimalsPerBatch(),
                updateBatchRequest.getAverageWeightPerAnimal(),
                updateBatchRequest.getBatchAge()
        );
        return new ResponseEntity<>(updatedBatch, HttpStatus.OK);
    }

    /**
     * Elimina un lote por su ID.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBatch(@PathVariable Long id) {
        batchDetailsService.deleteBatch(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Resta animales de un lote (por mortalidad o venta).
     */
    @PatchMapping("/{id}/remove-animals")
    public ResponseEntity<BatchEntity> removeAnimalsFromBatch(
            @PathVariable Long id,
            @RequestParam Integer animalsToRemove) {
        BatchEntity updatedBatch = batchDetailsService.removeAnimalsFromBatch(id, animalsToRemove);
        return new ResponseEntity<>(updatedBatch, HttpStatus.OK);
    }

}
