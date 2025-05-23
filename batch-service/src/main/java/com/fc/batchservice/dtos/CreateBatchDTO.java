package com.fc.batchservice.dtos;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateBatchDTO {

    @NotNull(message = "La cantidad de animales por lote no puede ser nula")
    @Min(value = 1, message = "La cantidad de animales por lote debe ser mayor que 0")
    private Integer quantityAnimalsPerBatch;

    @NotNull(message = "El peso promedio por animal no puede ser nulo")
    @Min(value = 0, message = "El peso promedio por animal debe ser mayor o igual a 0")
    private Double averageWeightPerAnimal;

    @NotNull(message = "La fecha de ingreso no puede ser nula")
    private LocalDate entryDate;

    @NotNull(message = "La edad del lote no puede ser nula")
    @Min(value = 0, message = "La edad del lote debe ser mayor o igual a 0")
    private Integer batchAge;

}
