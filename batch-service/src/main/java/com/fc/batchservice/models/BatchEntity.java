package com.fc.batchservice.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Table
@Entity
public class BatchEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long batchId;

    @NotNull
    private Integer quantityAnimalsPerBatch;

    @NotNull
    private Double averageWeightPerAnimal;

    @NotNull
    private LocalDateTime entryDate;

    @NotNull
    private Integer batchAge;

    private Integer animalsRemoved;

  /*  @ManyToMany
    @JoinTable(
            name = "batch_pound",
            joinColumns = @JoinColumn(name = "batch_id"),
            inverseJoinColumns = @JoinColumn(name = "pound_id")
    )
    private Set<PoundEntity> occupiedPounds; // Relación ManyToMany con PoundEntity*/

}
