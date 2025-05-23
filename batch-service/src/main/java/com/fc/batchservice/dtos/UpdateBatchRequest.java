package com.fc.batchservice.dtos;

import lombok.Getter;

@Getter
public class UpdateBatchRequest {

    private Integer quantityAnimalsPerBatch;
    private Double averageWeightPerAnimal;
    private Integer batchAge;

    public void setQuantityAnimalsPerBatch(Integer quantityAnimalsPerBatch) {
        this.quantityAnimalsPerBatch = quantityAnimalsPerBatch;
    }

    public void setAverageWeightPerAnimal(Double averageWeightPerAnimal) {
        this.averageWeightPerAnimal = averageWeightPerAnimal;
    }

    public void setBatchAge(Integer batchAge) {
        this.batchAge = batchAge;
    }

}
