package com.fc.batchservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateBatchDTO {

    private Integer quantityAnimalsPerBatch;
    private Double averageWeightPerAnimal;
    private Integer batchAge;

}
