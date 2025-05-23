package com.fc.batchservice.services;

import com.fc.batchservice.dtos.CreateBatchDTO;
import com.fc.batchservice.models.BatchEntity;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

public interface BatchDetailsService {

    /**
     * Crea un nuevo lote en la base de datos.
     *
     * @param createBatchDTO DTO con los datos necesarios para crear un lote.
     * @return El lote creado.
     */
    BatchEntity createBatch(CreateBatchDTO createBatchDTO);

    /**
     * Obtiene un lote por su ID.
     *
     * @param id ID del lote a buscar.
     * @return Un Optional que contiene el lote si existe, o vacío si no.
     */
    Optional<BatchEntity> getBatchById(Long id);

    /**
     * Obtiene todos los lotes registrados.
     *
     * @return Una lista con todos los lotes.
     */
    List<BatchEntity> getAllBatches();

    /**
     * Actualiza un lote existente.
     *
     * @param id             ID del lote a actualizar.
     * @param quantityAnimalsPerBatch Nueva cantidad de animales en el lote.
     * @param averageWeightPerAnimal  Nuevo peso promedio por animal.
     * @param batchAge               Nueva edad del lote.
     * @return El lote actualizado.
     */
    BatchEntity updateBatch(Long id, Integer quantityAnimalsPerBatch, Double averageWeightPerAnimal, Integer batchAge);

    /**
     * Elimina un lote por su ID.
     *
     * @param id ID del lote a eliminar.
     */
    void deleteBatch(Long id);

    /**
     * Resta la cantidad de animales de un lote debido a mortalidad o venta.
     *
     * @param id              ID del lote al que se le restarán los animales.
     * @param animalsToRemove Cantidad de animales a restar.
     * @return El lote actualizado con la nueva cantidad de animales.
     */
    BatchEntity removeAnimalsFromBatch(Long id, Integer animalsToRemove);

}
