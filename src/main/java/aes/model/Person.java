package aes.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class Person implements Serializable {
    private String firstName;
    private String lastname;
    private int age;
}
