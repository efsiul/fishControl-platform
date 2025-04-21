package com.fc.supplyservice.controllers;

import com.fc.supplyservice.models.ESupplyType;
import com.fc.supplyservice.models.SupplyEntity;
import com.fc.supplyservice.dtos.CreateSupplyDTO;
import com.fc.supplyservice.services.SupplyDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("api/supplies")
public class SupplyController {

    @Autowired
    private SupplyDetailsService supplyDetailsService;

    // CREATE - Crear un nuevo insumo
    @PostMapping
    public ResponseEntity<?> createSupply(@RequestBody CreateSupplyDTO supplyDTO) {
        // Validar que la fecha no sea nula
        if (supplyDTO.getSuppliesDate() == null) {
            return ResponseEntity.badRequest()
                    .body("La fecha del insumo no puede ser nula");
        }

        // Validar que la cantidad no sea 0 o negativa
        if (supplyDTO.getSuppliesQuantity() == null || supplyDTO.getSuppliesQuantity() <= 0) {
            return ResponseEntity.badRequest()
                    .body("La cantidad del insumo debe ser mayor que cero");
        }

        // Validar que el precio no sea 0 o negativo
        if (supplyDTO.getSuppliesPrice() == null || supplyDTO.getSuppliesPrice() <= 0) {
            return ResponseEntity.badRequest()
                    .body("El precio del insumo debe ser mayor que cero");
        }

        SupplyEntity supply = new SupplyEntity();
        supply.setSuppliesName(supplyDTO.getSuppliesName());
        supply.setPresentation(supplyDTO.getPresentation());
        supply.setSuppliesQuantity(supplyDTO.getSuppliesQuantity());
        supply.setSuppliesPrice(supplyDTO.getSuppliesPrice());
        supply.setSuppliesDate(supplyDTO.getSuppliesDate());
        supply.setType(supplyDTO.getType());

        // Solo establecer el stage si el tipo es FOOD, de lo contrario establecerlo como null
        if (supplyDTO.getType() == ESupplyType.FOOD) {
            supply.setStage(supplyDTO.getStage());
        } else {
            supply.setStage(null);
        }

        SupplyEntity createdSupply = supplyDetailsService.createSupply(supply);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdSupply);
    }


    // READ - Obtener todos los insumos
    @GetMapping
    public ResponseEntity<List<SupplyEntity>> getAllSupplies() {
        List<SupplyEntity> supplies = supplyDetailsService.getAllSupplies();
        return ResponseEntity.ok(supplies);
    }

    // READ - Obtener un insumo por ID
    @GetMapping("/{id}")
    public ResponseEntity<SupplyEntity> getSupplyById(@PathVariable Long id) {
        Optional<SupplyEntity> supply = supplyDetailsService.getSupplyById(id);
        return supply.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // READ - Obtener insumos por nombre
    @GetMapping("/name/{name}")
    public ResponseEntity<?> getSupplyByName(@PathVariable String name) {
        List<SupplyEntity> supplies = supplyDetailsService.getSupplyByName(name);

        if (supplies.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(supplies);
    }

    // UPDATE - Actualizar un insumo existente
    @PutMapping("/{id}")
    public ResponseEntity<SupplyEntity> updateSupply(@PathVariable Long id, @RequestBody SupplyEntity supply) {
        // Validar que el stage solo se aplique a insumos de tipo FOOD
        if (supply.getType() != ESupplyType.FOOD) {
            supply.setStage(null);
        }

        SupplyEntity updatedSupply = supplyDetailsService.updateSupply(id, supply);
        return updatedSupply != null ?
                ResponseEntity.ok(updatedSupply) :
                ResponseEntity.notFound().build();
    }

    // DELETE - Eliminar un insumo
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSupply(@PathVariable Long id) {
        // Verificar si el insumo existe antes de eliminarlo
        Optional<SupplyEntity> existingSupply = supplyDetailsService.getSupplyById(id);
        if (existingSupply.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        supplyDetailsService.deleteSupply(id);
        return ResponseEntity.noContent().build();
    }
}