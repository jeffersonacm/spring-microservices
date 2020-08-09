package academy.devdojo.youtube.course.endpoint.model;

import lombok.*;
import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Table
@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Course implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull(message = "The fiel 'title' is mandatory")
    @Column(nullable = false)
    private String title;

}
